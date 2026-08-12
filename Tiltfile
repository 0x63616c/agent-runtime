# The only local topology starts from the typed Stack renderer. This file owns
# no infrastructure schema and is intentionally locked to OrbStack.
config.define_string('stack', usage='sole local Stack identity')
config.define_string('profile', usage='explicit local or CI Stack profile')
config.define_string('fixture-scenario', usage='explicit declared local-only fixture scenario')
config.define_string('ci-context', usage='generated private k3d CI context')
config.define_string('ci-registry-host', usage='generated loopback CI registry host')
config.define_string('ci-registry-host-from-cluster', usage='generated in-cluster CI registry host')
cfg = config.parse()
stack = cfg.get('stack', '')
profile = cfg.get('profile', 'local')
fixture_scenario = cfg.get('fixture-scenario', 'workspace-approval-reset-v1')
ci_context = cfg.get('ci-context', 'k3d-ar-ci-')
ci_registry_host = cfg.get('ci-registry-host', 'localhost:0')
ci_registry_host_from_cluster = cfg.get('ci-registry-host-from-cluster', 'k3d-ar-reg-.localhost:5000')
ci_context_prefix = 'k3d-ar-ci-'
allow_k8s_contexts(['orbstack', ci_context])

if not stack:
    fail('pass -- --stack=<lowercase-dns-label>')
if len(stack) > 40 or stack[0] == '-' or stack[-1] == '-':
    fail('--stack must be a lowercase DNS label up to 40 characters')
stack_remainder = stack
for allowed in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-']:
    stack_remainder = stack_remainder.replace(allowed, '')
if stack_remainder:
    fail('--stack must be a lowercase DNS label up to 40 characters')
if profile not in ['local', 'ci']:
    fail('--profile must be local or ci')
if profile == 'ci':
    if k8s_context() != ci_context or not ci_context.startswith(ci_context_prefix):
        fail('CI profile must use its generated private agent-runtime k3d context')
    ci_identity = ci_context[len(ci_context_prefix):]
    if not ci_identity or not ci_registry_host.startswith('localhost:') or ci_registry_host_from_cluster != 'k3d-ar-reg-' + ci_identity + '.localhost:5000':
        fail('CI infrastructure inputs must use generated agent-runtime k3d identities')
if profile != 'local' and fixture_scenario != 'workspace-approval-reset-v1':
    fail('fixture scenario is local-only')
ci_readiness_timeout = '12m' if profile == 'ci' else '10m'
ci_settings(readiness_timeout=ci_readiness_timeout)
if k8s_context() == 'orbstack' and profile != 'local':
    fail('the explicit orbstack context only permits the local profile')
if k8s_context() == ci_context and profile != 'ci':
    fail('the isolated CI k3d context only permits the ci profile')
if k8s_context() == ci_context:
    default_registry(ci_registry_host, host_from_cluster=ci_registry_host_from_cluster)

stack_file = '.runtime/dev/' + stack + '.stack.json'
render_command = 'go run ./tools/dev render --stack=' + stack + ' --output=' + stack_file
if profile == 'local':
    render_command = render_command + ' --fixture-scenario=' + fixture_scenario
local(render_command, quiet=True)
stack_manifests = local('go run ./cmd/stackctl manifests --stack-file ' + stack_file + ' --profile ' + profile, quiet=True)
secret_manifests = local('go run ./tools/dev secrets --stack=' + stack + ' --profile=' + profile + ' --root=.', quiet=True)
k8s_yaml([stack_manifests, secret_manifests])

for workload in ['api', 'orchestration', 'model', 'tool', 'blob-role', 'codec', 'sandbox-control', 'sandbox-host', 'egress-proxy']:
    # Keep Tilt's incremental context aligned with every Dockerfile COPY.
    # Omitting a Go package here makes the CI-only context compile differently
    # from the sealed production context and fails only after deployment starts.
    docker_build('agent-runtime-dev/' + stack + '/' + workload, '.', dockerfile='deploy/production/Dockerfile', only=['cmd/runtime', 'cmd/agent-runtime-api', 'cmd/egress-proxy', 'internal', 'sandbox', 'temporalpayload', 'sdk/go', 'deploy/production/Dockerfile', 'go.mod', 'go.sum'])

# The declared profile owns every dependency and policy. Tilt only orders the
# reviewed resources and substitutes its stack-scoped development images.
k8s_resource('state', pod_readiness='wait')
k8s_resource('temporal-state', pod_readiness='wait')
k8s_resource('temporal', resource_deps=['temporal-state'], pod_readiness='wait')
# The local Stack's private bootstrap capability is created before Tilt starts.
# Reconciliation is a separately audited operator action and runs only after
# the owned Temporal Deployment reports Ready; runtime processes never create
# their own namespace as a startup side effect.
local_resource('stack-reconcile', cmd='go run ./tools/dev reconcile --stack=' + stack + ' --root=.', resource_deps=['temporal', 'migration-runner'])
k8s_resource('blob', pod_readiness='wait')
k8s_resource('telemetry', pod_readiness='wait')
k8s_resource('egress-proxy', pod_readiness='wait')
k8s_resource('migration-runner', resource_deps=['state'], pod_readiness='wait')
k8s_resource('api', resource_deps=['state', 'telemetry'], pod_readiness='wait', links=[link('http://api:8080/readyz', 'API runtime readiness')])
k8s_resource('orchestration', resource_deps=['state', 'temporal', 'telemetry'], pod_readiness='wait', links=[link('http://orchestration:8081/readyz', 'Orchestration runtime readiness')])
k8s_resource('model', resource_deps=['api', 'egress-proxy', 'telemetry'], pod_readiness='wait')
k8s_resource('tool', resource_deps=['api', 'sandbox-control', 'telemetry'], pod_readiness='wait')
k8s_resource('blob-role', resource_deps=['blob', 'telemetry'], pod_readiness='wait')
k8s_resource('codec', resource_deps=['blob', 'telemetry'], pod_readiness='wait', links=[link('http://codec:8085/readyz', 'Codec runtime readiness'), link('https://0x63616c.github.io/agent-runtime/', 'Agent Runtime docs')])
k8s_resource('sandbox-control', resource_deps=['state', 'telemetry'], pod_readiness='wait')
k8s_resource('sandbox-host', resource_deps=['sandbox-control', 'telemetry'], pod_readiness='wait')
