---
services: Azure-Stack, virtual-machines, key-vault
platforms: python
author: viananth
---

# Hybrid-KeyVault-Python-Deploy-Certificates-To-VM

This sample explains how you can create a VM in Python, with certificates installed automatically from a Key Vault account in Azure Stack.

## Getting Started

### Installation

1. If you don't already have it, [install Python](https://www.python.org/downloads/).

    This sample (and the SDK) is compatible with Python 2.7, 3.4, 3.5, 3.6 and 3.7.

1. We recommend that you use a [virtual environment](https://docs.python.org/3/tutorial/venv.html)
    to run this example, but it's not required.
    Install and initialize the virtual environment with the "venv" module on Python 3 (you must install [virtualenv](https://pypi.python.org/pypi/virtualenv) for Python 2.7):

    ```shell
    python -m venv mytestenv # Might be "python3" or "py -3.6" depending on your Python installation
    cd mytestenv
    source bin/activate      # Linux shell (Bash, ZSH, etc.) only
    ./scripts/activate       # PowerShell only
    ./scripts/activate.bat   # Windows CMD only
    ```

1. Create a [service principal](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals) to work against AzureStack. Make sure your service principal has [contributor/owner role](https://docs.microsoft.com/en-us/azure/azure-stack/azure-stack-create-service-principals#assign-role-to-service-principal) on your subscription.

1. Clone the repository.

    ```shell
    git clone https://github.com/Azure-Samples/Hybrid-KeyVault-Python-Deploy-Certificates-To-VM.git
    ```

1. Install the dependencies using pip.

    ```shell
    cd Hybrid-KeyVault-Python-Deploy-Certificates-To-VM
    pip install -r requirements.txt
    ```

1. Export these environment variables into your current shell or update the credentials in the example file.

    ```shell
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your client id}
    export AZURE_CLIENT_SECRET={your client secret}
    export AZURE_SUBSCRIPTION_ID={your subscription id}
    export AZURE_RESOURCE_LOCATION={your AzureStack resource location}
    export ARM_ENDPOINT={your AzureStack resource manager endpoint}
    ```

1. Run the sample.

    ```shell
    python example.py
    ```

## Demo

### Preliminary operations

This example setup some preliminary components that are no the topic of this sample and do not differ
from regular scenarios:

- A Resource Group
- A Virtual Network
- A Subnet
- A Public IP
- A Network Interface

For details about creation of these components, you can refer to the generic samples:

- [Resource Group](https://github.com/Azure-Samples/Hybrid-ResourceManager-Python-Manage-Resources)
- [Network and VM](https://github.com/Azure-Samples/Hybrid-Compute-Python-Manage-VM)

### Creating a KeyVault account enabled for deployment

```python
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
```

You can also find different example on how to create a Key Vault account:

- From CLI 2.0: https://docs.microsoft.com/azure/key-vault/key-vault-manage-with-cli2
- From Python SDK: https://github.com/Azure-Samples/Hybrid-KeyVault-Python-Manage-Secrets

> In order to execute this sample, your Key Vault account MUST have the "enabled-for-deployment" special permission. The EnabledForDeployment flag explicitly gives Azure (Microsoft.Compute resource provider) permission to use the certificates stored as secrets for this deployment.

> Note that access policy takes an *object_id*, not a client_id as parameter. This samples also provide a quick way to convert a Service Principal client_id to an object_id using the `azure-graphrbac` client.

### Prepare a certificate to store as secret in Keyvault

In Azure Stack, you need to store the certificate as a secret. Follow the steps provided [here](https://docs.microsoft.com/en-us/azure/azure-stack/user/azure-stack-key-vault-push-secret-into-vm#create-a-key-vault-secret) to prepare a certificate and convert it into a BASE64 Encoded string. Provide this certificate as string value in the sample as the secret.

```python
    certificate_name = "cert1"
    print('\nCreate Key Vault certificate as a secret')
    cert_value = '<Provide your certificate as a base64 encoded string value>'
    kv_client.set_secret(
        vault.properties.vault_uri, certificate_name, cert_value)

```

### Create a VM with Certificates from Key Vault

First, get your certificate as a Secret object:

```python
    certificate_as_secret = kv_client.get_secret(
        vault.properties.vault_uri,
        certificate_name,
        "" # Latest version
    )
```

During the creation of the VM, use the `secrets` atribute to assign your certificate:.

```python
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

vm_poller = compute_client.virtual_machines.create_or_update(
    GROUP_NAME,
    VM_NAME,
    params_create,
)
vm_result = vm_poller.result()
```

## Resources

- https://azure.microsoft.com/services/key-vault/
- https://github.com/Azure/azure-sdk-for-python
- https://docs.microsoft.com/python/api/overview/azure/key-vault
- https://docs.microsoft.com/en-us/azure/azure-stack/user/azure-stack-version-profiles-python
