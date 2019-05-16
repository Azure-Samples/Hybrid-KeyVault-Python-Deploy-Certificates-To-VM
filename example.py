"""Deploy Certificates to VMs from customer-managed Key Vault in Python.
"""
import logging
import os
import time

from azure.common.credentials import ServicePrincipalCredentials

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault import KeyVaultClient
from azure.keyvault.v2016_10_01.models import *
from azure.graphrbac import GraphRbacManagementClient
from azure.profiles import KnownProfiles
from haikunator import Haikunator
from msrestazure.azure_cloud import get_cloud_from_metadata_endpoint

HAIKUNATOR = Haikunator()

# Uncomment this if you want to see detailed log
# logging.basicConfig(level=logging.DEBUG)

# Resource location

LOCATION = os.environ['AZURE_RESOURCE_LOCATION']
GROUP_NAME = 'azure-kv-vm-certificate-sample-group'

# KeyVault

KV_NAME = HAIKUNATOR.haikunate() # Random name to avoid collision executing this sample

# Network

VNET_NAME = 'azure-sample-vnet'
SUBNET_NAME = 'azure-sample-subnet'
PUBLIC_IP_NAME = 'azure-sample-pip'
NIC_NAME = 'azure-sample-nic'
IP_CONFIG_NAME = 'azure-sample-ip-config'

# VM

VM_NAME = 'azuretestvm'
ADMIN_LOGIN = 'Foo12'
ADMIN_PASSWORD = 'BaR@123' + GROUP_NAME

def get_credentials():
    mystack_cloud = get_cloud_from_metadata_endpoint(
        os.environ['ARM_ENDPOINT'])
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID'],
        cloud_environment=mystack_cloud
    )
    return credentials, subscription_id, mystack_cloud


# Create a Linux VM with Key Vault certificates installed at creation.
#
# This script expects that the following environment vars are set:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Application Client ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Secret
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
# ARM_ENDPOINT: with your Azure Stack resource manager endpoint
# AZURE_RESOURCE_LOCATION: with your Azure Stack resource location
#
def run_example():
    """ARM Template deployment example."""
    #
    # Create the following RP Clients with an Application (service principal) token provider
    #

    KnownProfiles.default.use(KnownProfiles.v2019_03_01_hybrid)

    credentials, subscription_id, mystack_cloud = get_credentials()
    resource_client = ResourceManagementClient(credentials, subscription_id,
        base_url=mystack_cloud.endpoints.resource_manager)
    compute_client = ComputeManagementClient(credentials, subscription_id,
        base_url=mystack_cloud.endpoints.resource_manager)
    network_client = NetworkManagementClient(credentials, subscription_id, 
        base_url=mystack_cloud.endpoints.resource_manager)
    kv_mgmt_client = KeyVaultManagementClient(credentials, subscription_id, 
        base_url=mystack_cloud.endpoints.resource_manager)

    kv_credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID'],
        cloud_environment=mystack_cloud
    )
    kv_client = KeyVaultClient(kv_credentials)

    # Create Resource group
    print('\nCreate Resource Group')
    resource_group = resource_client.resource_groups.create_or_update(
        GROUP_NAME,
        {'location': LOCATION}
    )
    print_item(resource_group)

    # Resolve the client_id as object_id for KeyVault access policy.
    # If you already know your object_id, you can skip this part
    sp_object_id = resolve_service_principal(os.environ['AZURE_CLIENT_ID'])

    # Create Key Vault account
    print('\nCreate Key Vault account')
    vault = kv_mgmt_client.vaults.create_or_update(
        GROUP_NAME,
        KV_NAME,
        {
            'location': LOCATION,
            'properties': {
                'sku': {
                    'name': 'standard'
                },
                'tenant_id': os.environ['AZURE_TENANT_ID'],
                'access_policies': [{
                    'tenant_id': os.environ['AZURE_TENANT_ID'],
                    'object_id': sp_object_id,
                    'permissions': {
                        # Only "certificates" and "secrets" are needed for this sample
                        'certificates': ['all'],
                        'secrets': ['all']
                    }
                }],
                # Critical to allow the VM to download certificates later
                'enabled_for_deployment': True
            }
        }
    )
    print_item(vault)

    # KeyVault recommendation is to wait 20 seconds after account creation for DNS update
    time.sleep(20)

    # Create a certificate in the keyvault as a secret
    certificate_name = "cert1"
    print('\nCreate Key Vault Certificate as a secret')
    cert_value = '<Provide your certificate as a base64 encoded string value>'
    kv_client.set_secret(
        vault.properties.vault_uri, certificate_name, cert_value)

    print('\nGet Key Vault created certificate as a secret')
    certificate_as_secret = kv_client.get_secret(
        vault.properties.vault_uri,
        certificate_name,
        "" # Latest version
    )
    print_item(certificate_as_secret)

    print("\nCreate Network")
    # Create Network components of the VM
    # This is not related to the main topic of this sample and is just required to create the VM
    subnet = create_virtual_network(network_client)
    public_ip = create_public_ip(network_client)
    nic = create_network_interface(network_client, subnet, public_ip)
    print_item(nic)

    # Create a VM with some Key Vault certificates
    params_create = {
        'location': LOCATION,
        'hardware_profile': get_hardware_profile(),
        'network_profile': get_network_profile(nic.id),
        'storage_profile': get_storage_profile(),
        'os_profile': {
            'admin_username': ADMIN_LOGIN,
            'admin_password': ADMIN_PASSWORD,
            'computer_name': 'testkvcertificates',
            # This is the Key Vault critical part
            'secrets': [{
                'source_vault': {
                    'id': vault.id,
                },
                'vault_certificates': [{
                    'certificate_url': certificate_as_secret.id
                }]
            }]
        }
    }

    print("\nCreate VM")
    vm_poller = compute_client.virtual_machines.create_or_update(
        GROUP_NAME,
        VM_NAME,
        params_create,
    )
    vm_result = vm_poller.result()
    print_item(vm_result)

    # Get the PublicIP after VM creation, since assignment is dynamic
    public_ip = network_client.public_ip_addresses.get(
        GROUP_NAME,
        PUBLIC_IP_NAME
    )

    print("You can connect to the VM using:")
    print("ssh {}@{}".format(
        ADMIN_LOGIN,
        public_ip.ip_address,
    ))
    print("And password: {}\n".format(ADMIN_PASSWORD))

    print("Your certificate is available in this folder: /var/lib/waagent")
    print("You must be root to see it (sudo su)\n")

    input("Press enter to delete this Resource Group.")

    # Delete Resource group and everything in it
    print('Delete Resource Group')
    delete_async_operation = resource_client.resource_groups.delete(GROUP_NAME)
    delete_async_operation.wait()
    print("\nDeleted: {}".format(GROUP_NAME))

def print_item(group):
    """Print a ResourceGroup instance."""
    if hasattr(group, 'name'):
        print("\tName: {}".format(group.name))
    print("\tId: {}".format(group.id))
    if hasattr(group, 'location'):
        print("\tLocation: {}".format(group.location))
    print_properties(getattr(group, 'properties', None))

def print_properties(props):
    """Print a ResourceGroup propertyies instance."""
    if props and hasattr(props, 'provisioning_state'):
        print("\tProperties:")
        print("\t\tProvisioning State: {}".format(props.provisioning_state))
    print("\n\n")

def resolve_service_principal(identifier):
    """Get an object_id from a client_id.
    """
    graphrbac_credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID'],
        resource="https://graph.windows.net"
    )
    graphrbac_client = GraphRbacManagementClient(
        graphrbac_credentials,
        os.environ['AZURE_TENANT_ID']
    )

    result = list(graphrbac_client.service_principals.list(filter="servicePrincipalNames/any(c:c eq '{}')".format(identifier)))
    if result:
        return result[0].object_id
    raise RuntimeError("Unable to get object_id from client_id")

###### Network creation, not specific to MSI scenario ######

def create_virtual_network(network_client):
    """Usual VNet creation.
    """
    params_create = {
        'location': LOCATION,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16'],
        },
        'subnets': [{
            'name': SUBNET_NAME,
            'address_prefix': '10.0.0.0/24',
        }],
    }
    vnet_poller = network_client.virtual_networks.create_or_update(
        GROUP_NAME,
        VNET_NAME,
        params_create,
    )
    vnet_poller.wait()

    return network_client.subnets.get(
        GROUP_NAME,
        VNET_NAME,
        SUBNET_NAME,
    )

def create_public_ip(network_client):
    """Usual PublicIP creation.
    """
    params_create = {
        'location': LOCATION,
        'public_ip_allocation_method': 'dynamic',
    }
    pip_poller = network_client.public_ip_addresses.create_or_update(
        GROUP_NAME,
        PUBLIC_IP_NAME,
        params_create,
    )
    return pip_poller.result()

def create_network_interface(network_client, subnet, public_ip):
    """Usual create NIC.
    """
    params_create = {
        'location': LOCATION,
        'ip_configurations': [{
            'name': IP_CONFIG_NAME,
            'private_ip_allocation_method': "Dynamic",
            'subnet': subnet,
            'public_ip_address': {
                'id': public_ip.id
            }
        }]
    }
    nic_poller = network_client.network_interfaces.create_or_update(
        GROUP_NAME,
        NIC_NAME,
        params_create,
    )
    return nic_poller.result()

###### VM creation, not specific to this scenario ######

def get_hardware_profile():
    return {
        'vm_size': 'Standard_A0'
    }

def get_network_profile(network_interface_id):
    return {
        'network_interfaces': [{
            'id': network_interface_id,
        }],
    }

def get_storage_profile():
    return {
        'image_reference': {
            'publisher': 'Canonical',
            'offer': 'UbuntuServer',
            'sku': '16.04-LTS',
            'version': 'latest'
        }
    }

if __name__ == "__main__":
    run_example()
