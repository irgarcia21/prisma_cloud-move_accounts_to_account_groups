# IMPORTANT: update "API_config.ini" file before running the script. The following fields are currently empty and need to be updated:
```
URL --> introduce your API URL (e.g. "https://api2.eu.prismacloud.io")
ACCESS_KEY_ID --> introduce your Prisma Cloud ACCESS KEY ID
SECRET_KEY --> introduce your Prisma Cloud SECRET KEY
```
    
## Functioning description:

The script gets the current Account Groups in Prisma Cloud, checks if any Cloud Account in the default Account Group contains certain text and if so, it moves them to a custom Account Group.

**IMPORTANT**: GCP accounts will not be moved with this script. GCP accounts should be automated by Prisma Cloud.

## Applicable use cases:

The purpose of the script is to have dynamic adding of accounts to account groups. This is to make sure that all onboarded accounts are mapped to proper account groups automatically without manual intervention. The script can be run on a regular basis (e.g. daily) to constantly update the accounts.

The current code covers the exactly following scenario in its last lines:
- If any account with "test" in its name, it will be deleted from the default Account Group and added to the Account Group called "AccountGroup-test".
- If any account with "prod" in its name, it will be deleted from the default Account Group and added to the Account Group called "AccountGroup-prod".

That lines can be changed to cover different scenarios or use cases.
