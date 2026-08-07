def lifecycle($profile):
  if $profile == "production" then .
  elif .kind == "secret_reference" then
    .retention = {policy:"external",days:0} |
    .delete_behavior = "retain" |
    .backup_restore_owner = "none"
  else
    .retention = {policy:"ephemeral",days:0} |
    .delete_behavior = "delete" |
    .backup_restore_owner = "none"
  end;

def role_config_namespace($namespace):
  if .kubernetes then
    .kubernetes.environment |= ((. // []) | map(
      if .name == "RUNTIME_ROLE_CONFIG" then
        .value |= (fromjson |
          .namespace = $namespace |
          .dependencies |= map(.endpoint |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc")) |
          tojson)
      else . end))
  else . end;

def profile_resource($namespace; $profile):
  lifecycle($profile) |
  role_config_namespace($namespace) |
  if .kind == "secret_reference" then
    .secret_reference.provider = (if $profile == "production" then "external-secrets" else "local-generated" end) |
    .secret_reference.reference |= sub("^agent-runtime-"; $namespace + "-")
  elif .id == "temporal-namespace" then
    .orchestration.namespace = $namespace |
    .orchestration.task_queue_prefix = ($namespace + "-")
  elif .id == "blob-prefix" then
    .dependencies += ["blob-reconciler"] |
    .dependencies |= unique |
    .blob.bucket = $namespace |
    .blob.prefix = ($namespace + "/payloads") |
    .blob.reconciler_reference = "blob-reconciler"
  elif .id == "state" then
    .dependencies += ["state-data"] |
    .dependencies |= unique |
    .kubernetes.volume_mounts = [{claim:"state-data",path:"/var/lib/postgresql/data",read_only:false}]
  elif .id == "blob" then
    .dependencies += ["blob-data"] |
    .dependencies |= unique |
    .kubernetes.volume_mounts = [{claim:"blob-data",path:"/data",read_only:false}]
  elif .id == "telemetry" then
    .dependencies += ["telemetry-data"] |
    .dependencies |= unique |
    .kubernetes.environment = [
      {name:"SPAN_STORAGE_TYPE",value:"badger"},
      {name:"BADGER_EPHEMERAL",value:"false"},
      {name:"BADGER_DIRECTORY_VALUE",value:"/badger/data"},
      {name:"BADGER_SPAN_STORE_TTL",value:"720h"},
      {name:"COLLECTOR_OTLP_ENABLED",value:"true"}
    ] |
    .kubernetes.arguments = ["--badger.directory-key=/badger/key"] |
    .kubernetes.volume_mounts = [{claim:"telemetry-data",path:"/badger",read_only:false}]
  elif .id == "temporal" then
    .dependencies = ["temporal-account","temporal-auth-secret","temporal-db-secret","temporal-state-service"] |
    .kubernetes.environment |= map(
      if .name == "POSTGRES_SEEDS" then .value = "temporal-state"
      elif .name == "POSTGRES_USER" then .value = "temporal"
      else . end) |
    .kubernetes.secret_environment = [{name:"POSTGRES_PWD",secret:"temporal-db-secret",key:"POSTGRES_PASSWORD"}]
  elif .id == "temporal-egress" then
    .dependencies = ["temporal","temporal-state"] |
    .kubernetes.network.allowed_egress = ["temporal-state"]
  else . end;

def common($id; $kind; $owner; $profile; $body):
  ({
    id:$id, kind:$kind, owner:$owner, scope:"namespace", dependencies:[],
    retention:(if $profile == "production" then {policy:"persistent",days:30} else {policy:"ephemeral",days:0} end),
    backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
    delete_behavior:(if $profile == "production" then "retain" else "delete" end),
    external_controller:false
  } + $body);

def extras($namespace; $profile):
  [
    ({
      id:"temporal-db-secret",kind:"secret_reference",owner:"security-operator",scope:"namespace",dependencies:[],
      retention:{policy:"external",days:0},backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:"retain",external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-temporal-db-secret"),version:"v1",keys:["POSTGRES_PASSWORD"]}
    }),
    common("temporal-state-account";"kubernetes";"platform-operator";$profile;{kubernetes:{api_version:"v1",kind:"ServiceAccount",name:"temporal-state-account"}}),
    common("state-data";"kubernetes";"database-operator";$profile;{kubernetes:{api_version:"v1",kind:"PersistentVolumeClaim",name:"state-data",storage:[{name:"data",size_bytes:1073741824,class:"local-path"}]}}),
    common("temporal-state-data";"kubernetes";"database-operator";$profile;{kubernetes:{api_version:"v1",kind:"PersistentVolumeClaim",name:"temporal-state-data",storage:[{name:"data",size_bytes:1073741824,class:"local-path"}]}}),
    common("blob-data";"kubernetes";"blob-operator";$profile;{kubernetes:{api_version:"v1",kind:"PersistentVolumeClaim",name:"blob-data",storage:[{name:"data",size_bytes:1073741824,class:"local-path"}]}}),
    common("telemetry-data";"kubernetes";"telemetry-operator";$profile;{kubernetes:{api_version:"v1",kind:"PersistentVolumeClaim",name:"telemetry-data",storage:[{name:"data",size_bytes:1073741824,class:"local-path"}]}}),
    (common("temporal-state";"kubernetes";"database-operator";$profile;{kubernetes:{
      api_version:"apps/v1",kind:"Deployment",name:"temporal-state",replicas:1,
      image:"postgres@sha256:e5507c984377515b8c9922b0eb19f55aba2063fdc7bccf268cefd53133f97054",service_account:"temporal-state-account",
      environment:[{name:"POSTGRES_DB",value:"temporal"},{name:"POSTGRES_USER",value:"temporal"}],
      secret_environment:[{name:"POSTGRES_PASSWORD",secret:"temporal-db-secret",key:"POSTGRES_PASSWORD"}],
      volume_mounts:[{claim:"temporal-state-data",path:"/var/lib/postgresql/data",read_only:false}],
      readiness:{command:["pg_isready","-U","temporal","-d","temporal"],initial_delay_seconds:1,period_seconds:5,failure_threshold:12},
      ports:[{name:"http",number:5432,protocol:"TCP"}],compute:{request_milli_cpu:100,limit_milli_cpu:500,request_memory_bytes:134217728,limit_memory_bytes:536870912},storage:[]
    }}) | .dependencies=["temporal-state-account","temporal-state-data","temporal-db-secret"]),
    (common("temporal-state-service";"kubernetes";"platform-operator";$profile;{kubernetes:{api_version:"v1",kind:"Service",name:"temporal-state",selector:"temporal-state",ports:[{name:"http",number:5432,protocol:"TCP"}]}}) | .dependencies=["temporal-state"]),
    (common("temporal-state-egress";"kubernetes";"security-operator";$profile;{kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"temporal-state-egress",network:{default_deny:true,subject:"temporal-state",allowed_egress:[]}}}) | .dependencies=["temporal-state"]),
    (common("blob-reconciler";"kubernetes";"blob-operator";$profile;{kubernetes:{
      api_version:"apps/v1",kind:"Deployment",name:"blob-reconciler",replicas:1,
      image:"minio/mc@sha256:aead63c77f9db9107f1696fb08ecb0faeda23729cde94b0f663edf4fe09728e3",service_account:"blob-account",
      command:["/bin/sh"],arguments:["-c","trap : TERM INT; sleep infinity & wait"],environment:[],
      secret_environment:[{name:"MINIO_ROOT_USER",secret:"blob-storage-secret",key:"MINIO_ROOT_USER"},{name:"MINIO_ROOT_PASSWORD",secret:"blob-storage-secret",key:"MINIO_ROOT_PASSWORD"}],
      ports:[],compute:{request_milli_cpu:25,limit_milli_cpu:100,request_memory_bytes:33554432,limit_memory_bytes:134217728},storage:[]
    }}) | .dependencies=["blob-account","blob-storage-secret","blob-service"]),
    (common("blob-reconciler-egress";"kubernetes";"security-operator";$profile;{kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"blob-reconciler-egress",network:{default_deny:true,subject:"blob-reconciler",allowed_egress:["blob"]}}}) | .dependencies=["blob-reconciler","blob"]),
    ({
      id:"temporal-persistence",kind:"database",owner:"database-operator",scope:"namespace",dependencies:["temporal","temporal-db-secret","temporal-state"],
      retention:(if $profile == "production" then {policy:"persistent",days:30} else {policy:"ephemeral",days:0} end),
      backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      database:{database:"temporal",schema:"public",connection_reference:"temporal-db-secret",migration_target:"temporal-state",migrations:[]}
    })
  ];

def resources_for($base; $namespace; $profile):
  (($base | map(profile_resource($namespace; $profile))) + extras($namespace; $profile));

(.profiles.production.resources) as $base |
.profiles.local.resources = resources_for($base; .profiles.local.namespace; "local") |
.profiles.ci.resources = resources_for($base; .profiles.ci.namespace; "ci") |
.profiles.production.resources = resources_for($base; .profiles.production.namespace; "production")
