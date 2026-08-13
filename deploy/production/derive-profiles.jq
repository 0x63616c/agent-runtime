def lifecycle($profile):
  if $profile == "production" then .
  elif .kind == "secret_reference" then
    .retention = {policy:"ephemeral",days:0} |
    .delete_behavior = "delete" |
    .backup_restore_owner = "none"
  else
    .retention = {policy:"ephemeral",days:0} |
    .delete_behavior = "delete" |
    .backup_restore_owner = "none"
  end;

def role_config_namespace($namespace; $profile):
  if .kubernetes then
    .kubernetes.environment |= ((. // []) | map(
      if .name == "RUNTIME_ROLE_CONFIG" then
        .value |= (fromjson |
          .namespace = $namespace |
          .dependencies |= map(.endpoint |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc")) |
          if .worker then
            .worker.payload_blob_endpoint |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc") |
            .worker.payload_blob_bucket = ($namespace + "-temporal-payload") |
            .worker.task_queue = ($namespace + "-session-v1")
          else . end |
          if .tool_dispatch then
            .tool_dispatch.content_endpoint |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc") |
            .tool_dispatch.content_bucket = $namespace |
            .tool_dispatch.control_server_name |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc") |
            .tool_dispatch.server_name |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc")
          else . end |
          tojson)
      elif .name == "RUNTIME_API_CONFIG" then
        .value |= (fromjson |
      .profile = $profile |
          if $profile == "local" then
            .storage.content.endpoint = ("http://blob." + $namespace + ".svc:9000") |
      del(.storage.content.ca_file)
          else
            .storage.content.endpoint |= gsub("\\.agent-runtime\\.svc"; "." + $namespace + ".svc") |
      .storage.content.ca_file = "/etc/agent-runtime/blob-ca.crt"
          end |
          .storage.content.bucket = $namespace |
          tojson)
      else . end))
  else . end;

# This explicit local-only operator fixture is the sole deterministic provider
# used by the disposable Tilt demonstration. It is not derived into CI or
# production and has no production credential or provider claim.
def local_demo_fixture($namespace; $profile):
  if $profile != "local" then .
  elif .id == "model" or .id == "tool" then
    .kubernetes.environment |= map(
      if .name == "RUNTIME_ROLE_CONFIG" then
        .value |= (fromjson |
          .local_demo_worker = {enabled:true,mode:"local-demo-v1",fixture:"workspace-approval-v1",fixture_scenario:"workspace-approval-reset-v1",state_dsn_environment:"LOCAL_DEMO_STATE_DSN",content_endpoint:("blob." + $namespace + ".svc:9000"),content_access_key_environment:"LOCAL_DEMO_CONTENT_ACCESS_KEY",content_secret_key_environment:"LOCAL_DEMO_CONTENT_SECRET_KEY",content_bucket:$namespace} |
          tojson)
      else . end) |
    .kubernetes.secret_environment += (if .id == "model" then
      [{name:"LOCAL_DEMO_STATE_DSN",secret:"model-secret",key:"LOCAL_DEMO_STATE_DSN"},{name:"LOCAL_DEMO_CONTENT_ACCESS_KEY",secret:"model-secret",key:"LOCAL_DEMO_CONTENT_ACCESS_KEY"},{name:"LOCAL_DEMO_CONTENT_SECRET_KEY",secret:"model-secret",key:"LOCAL_DEMO_CONTENT_SECRET_KEY"}]
    else
      [{name:"LOCAL_DEMO_STATE_DSN",secret:"tool-broker-secret",key:"LOCAL_DEMO_STATE_DSN"},{name:"LOCAL_DEMO_CONTENT_ACCESS_KEY",secret:"tool-broker-secret",key:"LOCAL_DEMO_CONTENT_ACCESS_KEY"},{name:"LOCAL_DEMO_CONTENT_SECRET_KEY",secret:"tool-broker-secret",key:"LOCAL_DEMO_CONTENT_SECRET_KEY"}]
    end)
  elif .id == "model-secret" or .id == "tool-broker-secret" then
    .secret_reference.keys += ["LOCAL_DEMO_STATE_DSN","LOCAL_DEMO_CONTENT_ACCESS_KEY","LOCAL_DEMO_CONTENT_SECRET_KEY"]
  elif .id == "model-egress" then
    .kubernetes.network.allowed_egress += ["blob","state"] | .kubernetes.network.allowed_egress |= unique
  elif .id == "tool-egress" and $profile == "local" then
    .dependencies |= map(select(. != "tool-dispatch")) |
    .kubernetes.network.allowed_egress = ["api","blob","otel-collector","state"]
  elif .id == "tool-egress" then
    .kubernetes.network.allowed_egress += ["blob","state"] | .kubernetes.network.allowed_egress |= unique
  else . end;

def dns_capability:
  if .kind == "kubernetes" and .kubernetes.kind == "NetworkPolicy" and ((.kubernetes.network.allowed_egress | length) > 0) then
    .kubernetes.network.allow_dns = true
  else
    del(.kubernetes.network.allow_dns)
  end;

def profile_resource($namespace; $profile):
  lifecycle($profile) |
  role_config_namespace($namespace; $profile) |
  local_demo_fixture($namespace; $profile) |
  dns_capability |
  if .id == "tool" and $profile == "local" then
    .dependencies |= map(select(. != "tool-dispatch-service" and . != "tool-dispatch-trust-secret")) |
    .kubernetes.secret_mounts = [] |
    .kubernetes.environment |= map(if .name == "RUNTIME_ROLE_CONFIG" then .value |= (fromjson | .dependencies |= map(if .name == "tool-broker" then .endpoint = ("http://api." + $namespace + ".svc:8080") else . end) | del(.tool_trigger) | tojson) else . end)
  elif .id == "tool" then
    .dependencies += ["tool-dispatch-service","tool-dispatch-trust-secret"] | .dependencies |= unique |
    .kubernetes.environment |= map(if .name == "RUNTIME_ROLE_CONFIG" then .value |= (fromjson | .dependencies |= map(if .name == "tool-broker" then .endpoint = ("https://tool-dispatch." + $namespace + ".svc:8089") else . end) | .tool_trigger = {server_name:("tool-dispatch." + $namespace + ".svc"),trust_bundle_ref:"trust/tool-dispatch",trust_bundle_path:"/run/tool-dispatch-client/ca.crt",interval_seconds:5} | tojson) else . end) |
    .kubernetes.secret_mounts = [{secret:"tool-dispatch-trust-secret",key:"TOOL_DISPATCH_SERVER_CA",path:"/run/tool-dispatch-client/ca.crt"}]
  elif .id == "tool-egress" and $profile == "local" then
    .dependencies |= map(select(. != "tool-dispatch")) |
    .kubernetes.network.allowed_egress = ["api","blob","otel-collector","state"]
  elif .id == "tool-egress" then
    .dependencies += ["tool-dispatch"] | .dependencies |= unique |
    .kubernetes.network.allowed_egress = ["tool-dispatch","otel-collector"]
  elif .id == "api" then
    .dependencies += ["blob-tls-secret"] | .dependencies |= unique |
    .kubernetes.secret_mounts = [{secret:"blob-tls-secret",key:"BLOB_TLS_CA",path:"/etc/agent-runtime/blob-ca.crt"}]
  elif .id == "blob" then
    .dependencies += ["blob-tls-secret"] | .dependencies |= unique |
    .kubernetes.secret_mounts = [
      {secret:"blob-tls-secret",key:"BLOB_TLS_CERT",path:"/etc/minio/certs/public.crt"},
      {secret:"blob-tls-secret",key:"BLOB_TLS_KEY",path:"/etc/minio/certs/private.key"}
    ] |
    if $profile != "local" then
      .kubernetes.arguments = ["server","--certs-dir","/etc/minio/certs","/data"] |
      .
    else . end
  elif .id == "blob-reconciler" then
    .dependencies += ["blob-tls-secret"] | .dependencies |= unique |
    .kubernetes.secret_mounts = [{secret:"blob-tls-secret",key:"BLOB_TLS_CA",path:"/etc/mc/certs/CAs/blob-ca.crt"}] |
    if $profile != "local" then
      .kubernetes.environment += [{name:"MC_CERTS_DIR",value:"/etc/mc/certs"}] |
      .kubernetes.arguments[1] |= sub("http://blob:9000"; "https://blob:9000")
    else . end
  else . end |
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
    .blob.endpoint_port_name = "http" |
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
  elif .id == "sandbox-host" and $profile != "production" then
    .dependencies += ["sandbox-host-bootstrap"] | .dependencies |= unique
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
      retention:(if $profile == "production" then {policy:"external",days:0} else {policy:"ephemeral",days:0} end),backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-temporal-db-secret"),version:"v1",keys:["POSTGRES_PASSWORD"]}
    }),
    ({
      id:"blob-tls-secret",kind:"secret_reference",owner:"security-operator",scope:"namespace",dependencies:[],
      retention:(if $profile == "production" then {policy:"external",days:0} else {policy:"ephemeral",days:0} end),backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-blob-tls-secret"),version:"v1",keys:["BLOB_TLS_CA","BLOB_TLS_CERT","BLOB_TLS_KEY"]}
    }),
    ({
      id:"tool-dispatch-secret",kind:"secret_reference",owner:"security-operator",scope:"namespace",dependencies:[],
      retention:(if $profile == "production" then {policy:"external",days:0} else {policy:"ephemeral",days:0} end),backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-tool-dispatch-secret"),version:"v1",keys:["TOOL_DISPATCH_STATE_DSN","TOOL_DISPATCH_CONTENT_ACCESS_KEY","TOOL_DISPATCH_CONTENT_SECRET_KEY","TOOL_DISPATCH_CONTROL_TOKEN"]}
    }),
    ({
      id:"tool-dispatch-tls-secret",kind:"secret_reference",owner:"security-operator",scope:"namespace",dependencies:[],
      retention:(if $profile == "production" then {policy:"external",days:0} else {policy:"ephemeral",days:0} end),backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-tool-dispatch-tls-secret"),version:"v1",keys:["TOOL_DISPATCH_TLS_CERT","TOOL_DISPATCH_TLS_KEY"]}
    }),
    ({
      id:"tool-dispatch-trust-secret",kind:"secret_reference",owner:"security-operator",scope:"namespace",dependencies:[],
      retention:(if $profile == "production" then {policy:"external",days:0} else {policy:"ephemeral",days:0} end),backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      secret_reference:{provider:(if $profile == "production" then "external-secrets" else "local-generated" end),reference:($namespace + "-tool-dispatch-trust-secret"),version:"v1",keys:["TOOL_DISPATCH_SERVER_CA","SANDBOX_CONTROL_CA"]}
    }),
    common("temporal-state-account";"kubernetes";"platform-operator";$profile;{kubernetes:{api_version:"v1",kind:"ServiceAccount",name:"temporal-state-account"}}),
    common("tool-dispatch-account";"kubernetes";"platform-operator";$profile;{kubernetes:{api_version:"v1",kind:"ServiceAccount",name:"tool-dispatch-account"}}),
    (common("tool-dispatch";"kubernetes";"runtime-operator";$profile;{kubernetes:{
      api_version:"apps/v1",kind:"Deployment",name:"tool-dispatch",replicas:1,image:"ghcr.io/0x63616c/agent-runtime@sha256:bef38a1e7b268a50db626879ada7e4fc7d9486641dfb76ca8d5d54f21f102603",service_account:"tool-dispatch-account",command:["/runtime"],arguments:["--config-env","RUNTIME_ROLE_CONFIG","--role","tool-dispatch"],
      environment:[{name:"RUNTIME_ROLE_CONFIG",value:"{\"version\":1,\"role\":\"tool-dispatch\",\"namespace\":\"agent-runtime\",\"listen_address\":\"0.0.0.0:8089\",\"dependencies\":[{\"name\":\"state\",\"endpoint\":\"postgres://state.agent-runtime.svc:5432/agent_runtime\",\"secret_environment\":\"TOOL_DISPATCH_STATE_DSN\"},{\"name\":\"content\",\"endpoint\":\"https://blob.agent-runtime.svc:9000\",\"secret_environment\":\"TOOL_DISPATCH_CONTENT_ACCESS_KEY\"},{\"name\":\"content-secret\",\"endpoint\":\"https://blob.agent-runtime.svc:9000\",\"secret_environment\":\"TOOL_DISPATCH_CONTENT_SECRET_KEY\"},{\"name\":\"sandbox-control\",\"endpoint\":\"https://sandbox-control.agent-runtime.svc:8086\",\"secret_environment\":\"TOOL_DISPATCH_CONTROL_TOKEN\"},{\"name\":\"tool-broker\",\"endpoint\":\"https://tool-dispatch.agent-runtime.svc:8089\",\"secret_environment\":\"TOOL_BROKER_TOKEN\"},{\"name\":\"telemetry\",\"endpoint\":\"http://otel-collector:4318\"}],\"tool_dispatch\":{\"content_endpoint\":\"https://blob.agent-runtime.svc:9000\",\"content_bucket\":\"agent-runtime\",\"content_access_key_environment\":\"TOOL_DISPATCH_CONTENT_ACCESS_KEY\",\"content_secret_key_environment\":\"TOOL_DISPATCH_CONTENT_SECRET_KEY\",\"control_server_name\":\"sandbox-control.agent-runtime.svc\",\"control_trust_bundle_ref\":\"trust/sandbox-control\",\"control_trust_bundle_path\":\"/run/tool-dispatch/trust/sandbox-control-ca.crt\",\"control_credential_environment\":\"TOOL_DISPATCH_CONTROL_TOKEN\",\"server_name\":\"tool-dispatch.agent-runtime.svc\",\"server_certificate_path\":\"/run/tool-dispatch/tls/tls.crt\",\"server_private_key_path\":\"/run/tool-dispatch/tls/tls.key\",\"peer_policy\":\"bearer-token-v1\"}}"}],
      secret_environment:[{name:"TOOL_BROKER_TOKEN",secret:"tool-broker-secret",key:"TOOL_BROKER_TOKEN"},{name:"TOOL_DISPATCH_STATE_DSN",secret:"tool-dispatch-secret",key:"TOOL_DISPATCH_STATE_DSN"},{name:"TOOL_DISPATCH_CONTENT_ACCESS_KEY",secret:"tool-dispatch-secret",key:"TOOL_DISPATCH_CONTENT_ACCESS_KEY"},{name:"TOOL_DISPATCH_CONTENT_SECRET_KEY",secret:"tool-dispatch-secret",key:"TOOL_DISPATCH_CONTENT_SECRET_KEY"},{name:"TOOL_DISPATCH_CONTROL_TOKEN",secret:"tool-dispatch-secret",key:"TOOL_DISPATCH_CONTROL_TOKEN"}],
      secret_mounts:[{secret:"tool-dispatch-tls-secret",key:"TOOL_DISPATCH_TLS_CERT",path:"/run/tool-dispatch/tls/tls.crt"},{secret:"tool-dispatch-tls-secret",key:"TOOL_DISPATCH_TLS_KEY",path:"/run/tool-dispatch/tls/tls.key"},{secret:"tool-dispatch-trust-secret",key:"SANDBOX_CONTROL_CA",path:"/run/tool-dispatch/trust/sandbox-control-ca.crt"}],readiness:{command:["/runtime","--config-env","RUNTIME_ROLE_CONFIG","--role","tool-dispatch","--check"],initial_delay_seconds:1,period_seconds:5,failure_threshold:12},ports:[{name:"https",number:8089,protocol:"TCP"}],compute:{request_milli_cpu:100,limit_milli_cpu:500,request_memory_bytes:134217728,limit_memory_bytes:536870912},storage:[]
    }}) | .dependencies=["tool-dispatch-account","tool-broker-secret","tool-dispatch-secret","tool-dispatch-tls-secret","tool-dispatch-trust-secret"]),
    (common("tool-dispatch-service";"kubernetes";"platform-operator";$profile;{kubernetes:{api_version:"v1",kind:"Service",name:"tool-dispatch",selector:"tool-dispatch",ports:[{name:"https",number:8089,protocol:"TCP"}]}}) | .dependencies=["tool-dispatch"]),
    (common("tool-dispatch-egress";"kubernetes";"security-operator";$profile;{kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"tool-dispatch-egress",network:{default_deny:true,subject:"tool-dispatch",allow_dns:true,allowed_egress:["state","blob","sandbox-control","otel-collector"],allowed_ingress:["tool"]}}}) | .dependencies=["tool-dispatch","tool","state","blob","sandbox-control","otel-collector"]),
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
      command:["/bin/sh"],arguments:["-ec","mc alias set runtime http://blob:9000 \"$MINIO_ROOT_USER\" \"$MINIO_ROOT_PASSWORD\" >/dev/null; mc mb --ignore-existing runtime/\"$BLOB_BUCKET\" >/dev/null; mc mb --ignore-existing runtime/\"$BLOB_TEMPORAL_BUCKET\" >/dev/null; exec sleep infinity"],environment:[{name:"BLOB_BUCKET",value:$namespace},{name:"BLOB_TEMPORAL_BUCKET",value:($namespace + "-temporal-payload")}],
      secret_environment:[{name:"MINIO_ROOT_USER",secret:"blob-storage-secret",key:"MINIO_ROOT_USER"},{name:"MINIO_ROOT_PASSWORD",secret:"blob-storage-secret",key:"MINIO_ROOT_PASSWORD"}],
      ports:[],compute:{request_milli_cpu:25,limit_milli_cpu:100,request_memory_bytes:67108864,limit_memory_bytes:268435456},storage:[]
    }}) | .dependencies=["blob-account","blob-storage-secret","blob-service"]),
    (common("blob-reconciler-egress";"kubernetes";"security-operator";$profile;{kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"blob-reconciler-egress",network:{default_deny:true,subject:"blob-reconciler",allow_dns:true,allowed_egress:["blob"]}}}) | .dependencies=["blob-reconciler","blob"]),
    ({
      id:"temporal-persistence",kind:"database",owner:"database-operator",scope:"namespace",dependencies:["temporal","temporal-db-secret","temporal-state"],
      retention:(if $profile == "production" then {policy:"persistent",days:30} else {policy:"ephemeral",days:0} end),
      backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      database:{database:"temporal",schema:"public",connection_reference:"temporal-db-secret",migration_target:"temporal-state",migrations:[]}
    }),
    ({
      id:"temporal-visibility-persistence",kind:"database",owner:"database-operator",scope:"namespace",dependencies:["temporal","temporal-db-secret","temporal-state"],
      retention:(if $profile == "production" then {policy:"persistent",days:30} else {policy:"ephemeral",days:0} end),
      backup_restore_owner:(if $profile == "production" then "platform-operator" else "none" end),
      delete_behavior:(if $profile == "production" then "retain" else "delete" end),external_controller:true,
      database:{database:"temporal_visibility",schema:"public",connection_reference:"temporal-db-secret",migration_target:"temporal-state",migrations:[]}
    })
  ] +
  (if $profile == "production" then [] else [
    (common("sandbox-host-bootstrap-config";"kubernetes";"runtime-operator";$profile;{kubernetes:{api_version:"v1",kind:"ConfigMap",name:"sandbox-host-bootstrap-config",data:{"config.json":"{\"version\":1,\"database_dsn_environment\":\"SANDBOX_STATE_DSN\",\"host_id\":\"sandbox-host-01\",\"tenant\":\"public\",\"pool\":\"local-ci-reference\",\"generation\":1,\"certificate_file\":\"/run/sandbox-host/tls.crt\",\"signing_key_file\":\"/run/sandbox-host/signing.key\",\"capability_digest\":\"sha256:ae18609e688c7ebaaa4fb083f199cdc096067a21a71dadaa0346a74e0ed5b762\",\"expires_at\":\"2030-01-01T00:00:00Z\"}"},environment:[]}})),
    (common("sandbox-host-bootstrap";"kubernetes";"runtime-operator";$profile;{kubernetes:{api_version:"batch/v1",kind:"Job",name:"sandbox-host-bootstrap",post_migration:true,image:"ghcr.io/0x63616c/agent-runtime@sha256:bef38a1e7b268a50db626879ada7e4fc7d9486641dfb76ca8d5d54f21f102603",service_account:"sandbox-host-account",command:["/sandbox-host-bootstrap"],arguments:["--config","/etc/sandbox-host-bootstrap/config.json"],secret_environment:[{name:"SANDBOX_STATE_DSN",secret:"sandbox-state-secret",key:"SANDBOX_STATE_DSN"}],ports:[],compute:{request_milli_cpu:100,limit_milli_cpu:250,request_memory_bytes:67108864,limit_memory_bytes:134217728},storage:[],config_map_mounts:[{config_map:"sandbox-host-bootstrap-config",key:"config.json",path:"/etc/sandbox-host-bootstrap/config.json"}],secret_mounts:[{secret:"sandbox-host-identity-secret",key:"SANDBOX_HOST_TLS_CERT",path:"/run/sandbox-host/tls.crt"},{secret:"sandbox-host-identity-secret",key:"SANDBOX_HOST_SIGNING_KEY",path:"/run/sandbox-host/signing.key"}],environment:[]}}) | .dependencies=["sandbox-control-database","sandbox-host-bootstrap-config","sandbox-host-identity-secret","sandbox-state-secret"]),
    (common("sandbox-host-bootstrap-egress";"kubernetes";"security-operator";$profile;{kubernetes:{api_version:"networking.k8s.io/v1",kind:"NetworkPolicy",name:"sandbox-host-bootstrap-egress",network:{default_deny:true,subject:"sandbox-host-bootstrap",allow_dns:true,allowed_egress:["state"]},environment:[]}}) | .dependencies=["sandbox-host-bootstrap","state"])
  ] end) | map(if .id == "sandbox-host-bootstrap" then .kubernetes.suspend = true else . end);

def resources_for($base; $namespace; $profile):
  (($base + extras($namespace; $profile)) | map(profile_resource($namespace; $profile)) | map(select($profile != "local" or (.id != "tool-dispatch" and .id != "tool-dispatch-service" and .id != "tool-dispatch-account" and .id != "tool-dispatch-egress" and .id != "tool-dispatch-secret" and .id != "tool-dispatch-tls-secret" and .id != "tool-dispatch-trust-secret"))));

def generated_extra:
  . == "temporal-db-secret" or . == "blob-tls-secret" or . == "tool-dispatch-secret" or . == "tool-dispatch-tls-secret" or . == "tool-dispatch-trust-secret" or . == "temporal-state-account" or . == "tool-dispatch-account" or . == "state-data" or
  . == "temporal-state-data" or . == "blob-data" or . == "telemetry-data" or
  . == "temporal-state" or . == "temporal-state-service" or . == "temporal-state-egress" or
  . == "blob-reconciler" or . == "blob-reconciler-egress" or . == "tool-dispatch" or . == "tool-dispatch-service" or . == "tool-dispatch-egress" or . == "temporal-persistence" or
  . == "temporal-visibility-persistence" or . == "sandbox-host-bootstrap" or . == "sandbox-host-bootstrap-config" or . == "sandbox-host-bootstrap-egress";

(.profiles.production.resources | map(select((.id | generated_extra) | not))) as $base |
.profiles.local.resources = resources_for($base; .profiles.local.namespace; "local") |
.profiles.ci.resources = resources_for($base; .profiles.ci.namespace; "ci") |
.profiles.production.resources = resources_for($base; .profiles.production.namespace; "production")
