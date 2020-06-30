###############################################
# Automate LogicMonitor Group & Role Creation #
###############################################

# Import ya stuff
import requests
import json
import hashlib
import base64
import time
import hmac
from pprint import pprint

# Name ya groups (EVERYTHING will take this name on)
name = input("Enter partner [or MSP customer] name: ")

# Add ya API creds
access_id = 'Access ID'
access_key = 'Access Key'
groups = ['collector', 'dashboard', 'resource', 'website', 'user', 'report', 'topology', 'role']

def invoke_lmapi(
        path: str, http_verb: str = "", query_params: str = "", body: dict = {}
    ):
        
        # Get current time in milliseconds
        epoch = str(int(time.time() * 1000))
       
        # Convert body to json if it was passed
        if bool(body):
            body = json.dumps(body)
            request_vars = http_verb + epoch + body + path
        
        # Otherwise we don't need the body (right, Siri?)
        else:
            request_vars = http_verb + epoch + path
        
        # Construct Portal URL
        url = (
            "https://PORTAL.logicmonitor.com/santaba/rest"
            + path
            + query_params
        )
        
        # Construct autograph
        signature = base64.b64encode(
            (
                hmac.new(
                    access_key.encode(),
                    msg=request_vars.encode(),
                    digestmod=hashlib.sha256,
                ).hexdigest()
            ).encode()
        )
        
        # Construct headers
        auth = "LMv1 " + access_id + ":" + signature.decode() + ":" + epoch
        headers = {
            "Content-Type": "application/json",
            "Authorization": auth,
            "X-Version": "3",
        }
        
        # Make request
        if http_verb == "GET":
            response = requests.get(url, headers=headers)
        elif http_verb == "POST":
            response = requests.post(url, data=body, headers=headers)
        elif http_verb == "PATCH":
            response = requests.patch(url, data=body, headers=headers)
        elif http_verb == "DELETE":
           response = requests.delete(url, data=body, headers=headers)
        elif http_verb == "PUT":
            response = requests.put(url, data=body, headers=headers)
        else:
            print("Error: Unknown Request type! Please check the http_verb.")

        #return response as object if code is 200 (OK)
        if response.status_code == requests.codes.ok:
            return json.loads(response.content)
        else:
            print(json.loads(response.content))
            response.raise_for_status()



#################
# Create Groups #
#################

for group in groups:
    body = {
        "name": name,
        "description": name + "'s group made by the API"
    }

colgrps = (invoke_lmapi('/setting/collector/groups', 'POST', '', body))
devgrps = (invoke_lmapi('/device/groups', 'POST', '', body))
webgrps = (invoke_lmapi('/website/groups', 'POST', '', body))
repgrps = (invoke_lmapi('/report/groups', 'POST', '', body))
usrgrps = (invoke_lmapi('/setting/admin/groups', 'POST', '', body))
topgrps = (invoke_lmapi('/topology/groups', 'POST', '', body))
netgrps = (invoke_lmapi('/setting/netscans/groups', 'POST', '', body))
rolgrps = (invoke_lmapi('/setting/role/groups', 'POST', '', body))
dasgrps = (invoke_lmapi('/dashboard/groups', 'POST', '', body))


###########################################################
# Insert Dashboards to ya New Group from a Template Group #
###########################################################

#Grab the fresh dashboard group id
dasgrp_id = dasgrps['id']

dashes = invoke_lmapi('/dashboard/groups', 'GET','?fields=id,name,fullPath,numOfDashboards')

#Grab templates from LM dashboard group
dashboards = invoke_lmapi('/dashboard/dashboards', 'GET', '?filter=groupName:"LogicMonitor Dashboards"')
dashboard_group = (next((dashboard_group for dashboard_group in dashes['items'] if dashboard_group["name"] == name), None))

#Insert templates
for dashboard in dashboards['items']:
    template = invoke_lmapi('/dashboard/dashboards/' + str(dashboard['id']), 'GET', '?template=true&format=json')
    body = {
        "name": dashboard['name'],
        "template": template,
        "description": dashboard['description'],
        "sharable": True,
        "groupId": dasgrp_id
    }

    invoke_lmapi('/dashboard/dashboards', 'POST', '', body)


################
# Add ya Roles #
################

#Grab the fresh role group id
rolgrp_id = rolgrps['id']

rolegroups = invoke_lmapi('/setting/role/groups', 'GET')

#Add role with permissions (in body) to the group with that r_id
for rolegroup in rolegroups['items']:
    if rolegroup['name']==name:
        body = {
            "name": rolgrps['name'],
            "description": "",
            "roleGroupId": rolgrps['id'],
            "requireEULA": False,
            "twoFARequired": False,
            "customHelpLabel": "",
            "customHelpURL": "",
            "userPermission": "write",
            "privileges": [
                {
                    "objectType": "dashboard_group",
                    "objectId": dasgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "host_group",
                    "objectId": devgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "remoteSession",
                    "objectId": dasgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "website_group",
                    "objectId": webgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "map",
                    "objectId": topgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "report_group",
                    "objectId": repgrps['id'],
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "setting",
                    "objectId": "netscangroup.*",
                    "objectName": "NetScans",
                    "operation": "write"
                },
                {
                    "objectType": "setting",
                    "objectId": "useraccess.personalinfo",
                    "objectName": "User Profile",
                    "operation": "write"
                },
                {
                    "objectType": "setting",
                    "objectId": "collectorgroup."+str(colgrps['id']),
                    "objectName": rolgrps['name'],
                    "operation": "write"
                },
                {
                    "objectType": "setting",
                    "objectId": "accesslog",
                    "objectName": "Access Logs",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "accountinfo",
                    "objectName": "Account Information",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "alert.*",
                    "objectName": "Alert Settings",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "datasource.*",
                    "objectName": "LogicModules",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "integration",
                    "objectName": "Integrations",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "messagetemplate",
                    "objectName": "Message Templates",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "opsnote",
                    "objectName": "Ops Notes",
                    "operation": "read"
                },
                {
                    "objectType": "setting",
                    "objectId": "role."+str(rolgrps['id']),
                    "objectName": rolgrps['name'],
                    "operation": "read"
                },
                {
                    "objectId": "useraccess.apitoken",
                    "objectName": "useraccess.apitoken",
                    "objectType": "setting",
                    "operation": "write"
                },
                {
                    "objectType": "help",
                    "objectId": "*",
                    "objectName": "*",
                    "operation": "read"
                },
                {
                    "objectType": "help",
                    "objectId": "chat",
                    "objectName": "help",
                    "operation": "write"
                },
                {
                    "objectType": "help",
                    "objectId": "chat",
                    "objectName": "help",
                    "operation": "write"
                },
                {
                    "objectType": "dashboard_group",
                    "objectId": "sharingwidget",
                    "objectName": "sharingwidget",
                    "operation": "write"
                },
                {
                    "objectType": "dashboard_group",
                    "objectId": "private",
                    "objectName": "private",
                    "operation": "write"
                },
                {
                    "objectType": "deviceDashboard",
                    "objectId": "",
                    "objectName": "deviceDashboard",
                    "operation": "write"
                },
                {
                    "objectType": "resourceMapTab",
                    "objectId": "*",
                    "objectName": "*",
                    "operation": "read",
                    "subOperation": ""
                },
                {
                    "objectType": "configNeedDeviceManagePermission",
                    "objectId": "",
                    "objectName": "configNeedDeviceManagePermission",
                    "operation": "write"
                }
            ]
        }
        invoke_lmapi('/setting/roles', 'POST', '', body)





# +1 to A Durham and S Weenig for their wisdom & guidance
