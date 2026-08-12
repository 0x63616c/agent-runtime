# The only local topology starts from the typed Stack renderer. This file owns
# no infrastructure schema and is intentionally locked to OrbStack.
allow_k8s_contexts('orbstack')
config.define_string('stack', usage='sole local Stack identity')
cfg = config.parse()
stack = cfg.get('stack', '')

if not stack:
    fail('pass -- --stack=<lowercase-dns-label>')
if len(stack) > 40 or stack[0] == '-' or stack[-1] == '-':
    fail('--stack must be a lowercase DNS label up to 40 characters')
stack_remainder = stack
for allowed in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-']:
    stack_remainder = stack_remainder.replace(allowed, '')
if stack_remainder:
    fail('--stack must be a lowercase DNS label up to 40 characters')
if k8s_context() != 'orbstack':
    fail('agent-runtime local development only permits the explicit orbstack context')

stack_file = '.runtime/dev/' + stack + '.stack.json'
local('go run ./tools/dev render --stack=' + stack + ' --output=' + stack_file, quiet=True)
stack_manifests = local('go run ./cmd/stackctl manifests --stack-file ' + stack_file + ' --profile local', quiet=True)
secret_manifests = local('go run ./tools/dev secrets --stack=' + stack + ' --root=.', quiet=True)
k8s_yaml([stack_manifests, secret_manifests])

for workload in ['api', 'orchestration', 'model', 'tool', 'blob-role', 'codec', 'sandbox-control', 'sandbox-host', 'egress-proxy']:
    docker_build('agent-runtime-dev/' + stack + '/' + workload, '.', dockerfile='deploy/production/Dockerfile', only=['cmd/runtime', 'cmd/egress-proxy', 'internal/roles', 'internal/egressproxy', 'deploy/production/Dockerfile', 'go.mod', 'go.sum'])

# The declared profile owns every dependency and policy. Tilt only orders the
# reviewed resources and substitutes its stack-scoped development images.
k8s_resource('state', pod_readiness='wait')
k8s_resource('temporal-state', pod_readiness='wait')
k8s_resource('temporal', resource_deps=['temporal-state'], pod_readiness='wait')
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
