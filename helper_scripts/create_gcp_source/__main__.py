import sys
from google.cloud import securitycenter_v2


def create_source(organization_id) -> dict:
    """
    Create a new findings source
    Args:
        organization_id: organization_id is the numeric ID of the organization. e.g.:organization_id = "111122222444"
    """
    client = securitycenter_v2.SecurityCenterClient()
    org_name = f"organizations/{organization_id}"

    response = client.list_sources(parent=org_name)

    source_exists = False
    for source in response:
        if source.display_name == "KubeBench":
            print(f"Found exisitng source: {source.name}")
            source_exists = True
            break

    if not source_exists:
        response = client.create_source(
            request={
                "parent": org_name,
                "source": {
                    "display_name": "KubeBench",
                    "description": "KubeBench is an open-source CIS and STIG scanning tool for Kubernetes",
                },
            }
        )
        print(f"Created Source: {response.name}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        create_source(sys.argv[1])
    else:
        print("Syntax: python __main__.py <GCP_ORGANIZATION_ID>")
