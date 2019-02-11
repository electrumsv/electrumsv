import os
import pprint
import subprocess
import sys

from vsts.vss_connection import VssConnection
from msrest.authentication import BasicAuthentication

azurepipelines_api_key = None

filename = os.path.expanduser('~/.azurepipelines_api_key')
if os.path.exists(filename):
    with open(filename) as f:
        azurepipelines_api_key = f.read().strip()

if "azurepipelines_api_key" in os.environ:
    azurepipelines_api_key = os.environ["azurepipelines_api_key"]

if azurepipelines_api_key is None:
    print("Please provide an Azure Pipelines access token with read build access.")
    print("You can do this via the 'Security' link on your profile.")
    sys.exit(1)

if len(sys.argv) != 2:
    print(f"{sys.argv[0]} <release tag>")
    sys.exit(1)

tag_name = sys.argv[1].strip()
result = subprocess.run([ "git", "rev-list", "-n", "1", sys.argv[1] ], stdout=subprocess.PIPE)
if result.returncode != 0:
    sys.exit(1)
tag_commit_hash = result.stdout.decode('utf-8')

personal_access_token = azurepipelines_api_key
organization_url = 'https://dev.azure.com/electrumsv'

# Create a connection to the org
credentials = BasicAuthentication('', personal_access_token)
connection = VssConnection(base_url=organization_url, creds=credentials)

build_client = connection.get_client('vsts.build.v4_1.build_client.BuildClient')

project_name = "ElectrumSV"

builds = build_client.get_builds(
    project=project_name, top=1, result_filter="succeeded", query_order="finishTimeDescending",
    branch_name="refs/heads/master", repository_id="electrumsv/electrumsv",
    repository_type="GitHub")
for build in builds:
    if build.source_version == tag_commit_hash:
        # This is the long-term ideal.
        break
    build_id = build.id
    artifact = build_client.get_artifact(build_id, "build-files")
    pprint.pprint(artifact.__dict__)
    pprint.pprint(artifact.resource.__dict__)
    break
