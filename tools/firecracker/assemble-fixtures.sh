#!/usr/bin/env bash

# Assemble the project-owned Firecracker fixture bundles and a candidate v2
# lock from already downloaded, immutable inputs. This is intentionally a
# review/publish step, never a protected-runner command: it does not upload
# assets, edit tools/firecracker/fixtures.lock, or launch a VM.
set -euo pipefail

if [ "$#" -ne 10 ]; then
  echo "usage: $0 OUTPUT-DIR REVISION FIRECRACKER-VERSION FIRECRACKER-ARCHIVE KERNEL-URL KERNEL-VERSION-ID KERNEL-FILE ROOTFS ATTESTATION SOURCE-DATE-EPOCH" >&2
  exit 2
fi

output_dir=$1
revision=$2
firecracker_version=$3
firecracker_archive=$4
kernel_url=$5
kernel_version_id=$6
kernel_file=$7
rootfs=$8
attestation=$9
source_date_epoch=${10}

if ! [[ "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  echo "REVISION must be an exact lowercase 40-character commit" >&2; exit 2
fi
if [ "$(git rev-parse HEAD)" != "$revision" ] || ! git diff --quiet || ! git diff --cached --quiet; then
  echo "assemble from a clean checkout at exactly REVISION" >&2; exit 2
fi
if ! [[ "$firecracker_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "FIRECRACKER-VERSION must be an exact release version" >&2; exit 2
fi
if ! [[ "$kernel_version_id" =~ ^[A-Za-z0-9._~-]+$ ]] || [[ "$kernel_version_id" == "main" || "$kernel_version_id" == "latest" ]]; then
  echo "KERNEL-VERSION-ID must be an immutable object version identifier" >&2; exit 2
fi
# A normal versioned-object endpoint must be fetched through the version ID.
# Firecracker's public CI bucket is a narrow exception: it exposes the current
# object body and its VersionId response header, but rejects anonymous GETs
# with that versionId query. The final lock never trusts that mutable download
# URL: it pins the independently reviewed byte-identical project release asset.
# Keep the observed VersionId in the input manifest so reviewers can reconcile
# the upstream object that produced the retained bytes.
if [[ "$kernel_url" == https://*"?versionId=$kernel_version_id" ]]; then
  :
elif [[ "$kernel_url" =~ ^https://s3\.amazonaws\.com/spec\.ccfc\.min/firecracker-ci/[0-9]{8}-[0-9a-f]{12}-[0-9]+/x86_64/vmlinux-[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  :
else
  echo "KERNEL-URL must be HTTPS with exactly the supplied versionId, or the canonical public Firecracker CI kernel object" >&2; exit 2
fi
if [[ "$source_date_epoch" =~ [^0-9] ]] || [ -z "$source_date_epoch" ]; then
  echo "SOURCE-DATE-EPOCH must be an integer" >&2; exit 2
fi
if [ -e "$output_dir" ]; then
  echo "OUTPUT-DIR must not already exist" >&2; exit 2
fi
for input in "$firecracker_archive" "$kernel_file" "$rootfs" "$attestation"; do
  if [ ! -f "$input" ]; then echo "required regular input is absent: $input" >&2; exit 2; fi
done
for required in go python3 tar sha256sum; do
  command -v "$required" >/dev/null || { echo "required command is absent: $required" >&2; exit 2; }
done

archive_prefix="release-${firecracker_version}-x86_64"
firecracker_member="$archive_prefix/firecracker-${firecracker_version}-x86_64"
jailer_member="$archive_prefix/jailer-${firecracker_version}-x86_64"
tar -tzf "$firecracker_archive" | grep -Fx "$firecracker_member" >/dev/null
tar -tzf "$firecracker_archive" | grep -Fx "$jailer_member" >/dev/null

mkdir -p "$output_dir/input" "$output_dir/bundles"
cp "$firecracker_archive" "$output_dir/input/firecracker-${firecracker_version}-x86_64.tgz"
cp "$kernel_file" "$output_dir/input/vmlinux"
cp "$kernel_file" "$output_dir/bundles/kernel-vmlinux"

agent="$output_dir/guest-agent"
./tools/firecracker/build-guest-agent.sh "$agent"

agent_sha="sha256:$(sha256sum "$agent" | awk '{print $1}')"
agent_size=$(wc -c < "$agent" | tr -d ' ')
rootfs_sha="sha256:$(sha256sum "$rootfs" | awk '{print $1}')"
rootfs_size=$(wc -c < "$rootfs" | tr -d ' ')

python3 - "$output_dir" "$revision" "$firecracker_version" "$kernel_url" "$kernel_version_id" "$agent_sha" "$agent_size" "$rootfs_sha" "$rootfs_size" <<'PY'
import hashlib, json, os, subprocess, sys
out, revision, version, kernel_url, version_id, agent_sha, agent_size, rootfs_sha, rootfs_size = sys.argv[1:]
def digest(path):
    data = open(path, 'rb').read()
    return {'sha256':'sha256:'+hashlib.sha256(data).hexdigest(), 'size_bytes':len(data)}
def write(name, value):
    with open(os.path.join(out, name), 'w', encoding='utf-8') as f:
        json.dump(value, f, sort_keys=True, separators=(',', ':'))
        f.write('\n')
go_version = subprocess.check_output(['go','version'], text=True).strip()
source_tree = subprocess.check_output(['git','archive','--format=tar',revision])
source_tree_digest = 'sha256:'+hashlib.sha256(source_tree).hexdigest()
inputs = {
  'schema_version':'agent-runtime.firecracker.fixture-inputs/v1',
  'source_revision':revision,
  'source_tree':{'sha256':source_tree_digest,'size_bytes':len(source_tree)},
  'guest_agent':{'recipe':'tools/firecracker/build-guest-agent.sh','source_paths':['tools/firecracker/guest-agent','internal/firecracker'],'toolchain':go_version,'output':{'sha256':agent_sha,'size_bytes':int(agent_size)}},
  'rootfs':{'recipe':'tools/firecracker/build-rootfs.sh','output':{'sha256':rootfs_sha,'size_bytes':int(rootfs_size)}},
  'kernel':{'url':kernel_url,'immutable_reference':'version-id:'+version_id},
  'firecracker_release':version,
}
write('guest-agent-inputs.json', inputs)
write('rootfs-inputs.json', inputs)
sbom = {'spdxVersion':'SPDX-2.3','SPDXID':'SPDXRef-DOCUMENT','name':'agent-runtime-firecracker-smoke-fixture','dataLicense':'CC0-1.0','documentNamespace':'https://github.com/0x63616c/agent-runtime/tree/'+revision,'creationInfo':{'creators':['Tool: assemble-fixtures.sh'],'created':'1970-01-01T00:00:00Z'},'packages':[{'SPDXID':'SPDXRef-Package-agent-runtime','name':'github.com/0x63616c/agent-runtime','versionInfo':revision,'downloadLocation':'NOASSERTION','licenseConcluded':'MIT','licenseDeclared':'MIT','copyrightText':'NOASSERTION'}]}
write('guest-agent-sbom.spdx.json', sbom)
write('rootfs-sbom.spdx.json', sbom)
PY

cp "$rootfs" "$output_dir/rootfs.ext4"
cp "$attestation" "$output_dir/rootfs-attestation.json"
mkdir "$output_dir/agent-bundle" "$output_dir/rootfs-bundle"
cp "$agent" "$output_dir/agent-bundle/guest-agent"
cp "$output_dir/guest-agent-inputs.json" "$output_dir/agent-bundle/guest-agent-inputs.json"
cp "$output_dir/guest-agent-sbom.spdx.json" "$output_dir/agent-bundle/guest-agent-sbom.spdx.json"
cp "$output_dir/rootfs.ext4" "$output_dir/rootfs-bundle/rootfs.ext4"
cp "$output_dir/rootfs-attestation.json" "$output_dir/rootfs-bundle/rootfs-attestation.json"
cp "$output_dir/rootfs-inputs.json" "$output_dir/rootfs-bundle/rootfs-inputs.json"
cp "$output_dir/rootfs-sbom.spdx.json" "$output_dir/rootfs-bundle/rootfs-sbom.spdx.json"

tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -C "$output_dir/agent-bundle" -czf "$output_dir/bundles/guest-agent-bundle.tar.gz" guest-agent guest-agent-inputs.json guest-agent-sbom.spdx.json
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -C "$output_dir/rootfs-bundle" -czf "$output_dir/bundles/rootfs-bundle.tar.gz" rootfs.ext4 rootfs-attestation.json rootfs-inputs.json rootfs-sbom.spdx.json

python3 - "$output_dir" "$revision" "$firecracker_version" "$kernel_url" "$kernel_version_id" "$firecracker_member" "$jailer_member" <<'PY'
import hashlib, json, os, sys, tarfile
out, revision, version, kernel_url, version_id, fc_member, jailer_member = sys.argv[1:]
def item(path):
    data = open(path, 'rb').read()
    return ('sha256:'+hashlib.sha256(data).hexdigest(), len(data))
def member(path, name):
    with tarfile.open(path, 'r:gz') as tar:
        f = tar.extractfile(name)
        if f is None: raise SystemExit('archive member absent: '+name)
        data = f.read()
    return ('sha256:'+hashlib.sha256(data).hexdigest(), len(data))
def json_item(name): return item(os.path.join(out,name))
fc_archive=os.path.join(out,'input','firecracker-'+version+'-x86_64.tgz')
kernel=os.path.join(out,'input','vmlinux')
root_bundle=os.path.join(out,'bundles','rootfs-bundle.tar.gz')
agent_bundle=os.path.join(out,'bundles','guest-agent-bundle.tar.gz')
fc_d, fc_s=item(fc_archive); kernel_d,kernel_s=item(kernel); root_bundle_d,root_bundle_s=item(root_bundle); agent_bundle_d,agent_bundle_s=item(agent_bundle)
fc_dig,fc_size=member(fc_archive,fc_member); jailer_dig,jailer_size=member(fc_archive,jailer_member)
root_d,root_s=item(os.path.join(out,'rootfs.ext4')); agent_d,agent_s=item(os.path.join(out,'guest-agent'))
root_inputs_d,root_inputs_s=json_item('rootfs-inputs.json'); root_sbom_d,root_sbom_s=json_item('rootfs-sbom.spdx.json'); agent_inputs_d,agent_inputs_s=json_item('guest-agent-inputs.json'); agent_sbom_d,agent_sbom_s=json_item('guest-agent-sbom.spdx.json')
base='https://github.com/0x63616c/agent-runtime/releases/download/commit-'+revision+'/'
lock={'version':'firecracker.fixtures/v2','fixture_version':'smoke-'+revision[:12], 'sources':[
 {'id':'firecracker-release','kind':'release-archive','url':'https://github.com/firecracker-microvm/firecracker/releases/download/'+version+'/firecracker-'+version+'-x86_64.tgz','immutable_reference':'release:'+version,'format':'tar.gz','sha256':fc_d,'size_bytes':fc_s,'license':'Apache-2.0'},
 {'id':'kernel','kind':'project-release-asset','url':base+'kernel-vmlinux','immutable_reference':'commit:'+revision,'format':'file','sha256':kernel_d,'size_bytes':kernel_s,'license':'GPL-2.0-only'},
 {'id':'rootfs','kind':'project-build','url':base+'rootfs-bundle.tar.gz','immutable_reference':'commit:'+revision,'format':'tar.gz','sha256':root_bundle_d,'size_bytes':root_bundle_s,'license':'LicenseRef-agent-runtime-rootfs-sbom'},
 {'id':'guest-agent','kind':'project-build','url':base+'guest-agent-bundle.tar.gz','immutable_reference':'commit:'+revision,'format':'tar.gz','sha256':agent_bundle_d,'size_bytes':agent_bundle_s,'license':'MIT'}],
 'artifacts':[
 {'name':'firecracker','source_id':'firecracker-release','member':fc_member,'sha256':fc_dig,'size_bytes':fc_size,'license':'Apache-2.0','platform':{'os':'linux','architecture':'amd64'}},
 {'name':'jailer','source_id':'firecracker-release','member':jailer_member,'sha256':jailer_dig,'size_bytes':jailer_size,'license':'Apache-2.0','platform':{'os':'linux','architecture':'amd64'}},
 {'name':'kernel','source_id':'kernel','sha256':kernel_d,'size_bytes':kernel_s,'license':'GPL-2.0-only','platform':{'os':'linux','architecture':'amd64'}},
 {'name':'rootfs','source_id':'rootfs','member':'rootfs.ext4','sha256':root_d,'size_bytes':root_s,'license':'LicenseRef-agent-runtime-rootfs-sbom','platform':{'os':'linux','architecture':'amd64'},'build':{'recipe_path':'tools/firecracker/build-rootfs.sh','source_revision':revision,'toolchain':'see rootfs-inputs.json','inputs_member':'rootfs-inputs.json','inputs_sha256':root_inputs_d,'inputs_size_bytes':root_inputs_s,'sbom_member':'rootfs-sbom.spdx.json','sbom_sha256':root_sbom_d,'sbom_size_bytes':root_sbom_s,'static':False,'guest_agent_sha256':agent_d,'attestation_member':'rootfs-attestation.json'}},
 {'name':'guest-agent','source_id':'guest-agent','member':'guest-agent','sha256':agent_d,'size_bytes':agent_s,'license':'MIT','platform':{'os':'linux','architecture':'amd64'},'build':{'recipe_path':'tools/firecracker/build-guest-agent.sh','source_revision':revision,'toolchain':'see guest-agent-inputs.json','inputs_member':'guest-agent-inputs.json','inputs_sha256':agent_inputs_d,'inputs_size_bytes':agent_inputs_s,'sbom_member':'guest-agent-sbom.spdx.json','sbom_sha256':agent_sbom_d,'sbom_size_bytes':agent_sbom_s,'static':True}}
]}
with open(os.path.join(out,'fixtures.lock.candidate.json'),'w') as f: json.dump(lock,f,sort_keys=True,separators=(',',':')); f.write('\n')
PY

# Exercise the candidate through the exact strict lock, digest, bundle-member,
# provenance, and rootfs-to-agent binding checks that the protected runner will
# use. This local preflight maps only the just-assembled files; it never fetches,
# publishes, changes a reviewed lock, or starts a VM.
go run ./cmd/firecracker-fixture-preflight \
  -lock "$output_dir/fixtures.lock.candidate.json" \
  -firecracker-archive "$output_dir/input/firecracker-${firecracker_version}-x86_64.tgz" \
  -kernel "$output_dir/input/vmlinux" \
  -rootfs-bundle "$output_dir/bundles/rootfs-bundle.tar.gz" \
  -guest-agent-bundle "$output_dir/bundles/guest-agent-bundle.tar.gz"

echo "candidate lock: $output_dir/fixtures.lock.candidate.json"
echo "review the original versioned kernel identity recorded in *-inputs.json, then publish kernel-vmlinux and the two bundles to the exact commit-$revision GitHub release; after independent byte verification, copy the reviewed candidate to tools/firecracker/fixtures.lock."
