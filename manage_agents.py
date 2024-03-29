#!/usr/bin/env python3

import os
import json
import dotenv
import urllib3
import requests
from base64 import b64encode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhManageAPI:
    def __init__(self):
        dotenv.load_dotenv()

        self.port = 55000
        self.protocol = 'https'
        self.host = os.getenv('HOST')
        self.user = os.getenv('USERNAME')
        self.password = os.getenv('PASSWORD')
        self.login_endpoint = 'security/user/authenticate'

        self.login_url = f"{self.protocol}://{self.host}:{self.port}/{self.login_endpoint}"
        self.basic_auth = f"{self.user}:{self.password}".encode()
        self.login_headers = {'Content-Type': 'application/json',
                              'Authorization': f'Basic {b64encode(self.basic_auth).decode()}'}

        print("Login request ...\n")
        self.token = self.get_token()

        self.requests_headers = {'Content-Type': 'application/json',
                                 'Authorization': f'Bearer {self.token}'}
        
        #print(f"\nRequest headers {self.requests_headers['Authorization']}\n")

    # Get bearer tokens for authenticating to WAZUH MANAGER
    def get_token(self):
        response = requests.post(self.login_url, headers = self.login_headers, verify = False)
        return json.loads(response.content.decode())['data']['token']

    # List all agents
    def list_agents(self):
        print("Listing agents:")
        url = f"{self.protocol}://{self.host}:{self.port}/agents?pretty=true"
        params = {
            'limit': 500,
            'select': 'id,name,group,ip,status'
        }

        response = requests.get(url, headers = self.requests_headers, params = params, verify=False)
        print(f"\nResponse:\n{response.text}")

    # List all group IDs
    def list_group_ids(self):
        print("Listing agent group IDs:")
        url = f"{self.protocol}://{self.host}:{self.port}/groups?pretty=true"
        params = {
            'limit': 500,
            'select': 'name,count'
        }

        response = requests.get(url, headers=self.requests_headers, params=params, verify=False)
        print(f"\nResponse:\n{response.text}")

    # Get overall agents status summary
    def get_agents_status_summary(self):
        print("Geting agents status summary:")
        url = f"{self.protocol}://{self.host}:{self.port}/agents/summary/status?pretty=true"

        response = requests.get(url, headers=self.requests_headers, verify=False)
        print(f"\nResponse:\n{response.text}")

    # Get all agents inside a group ID
    def get_agents_in_a_group(self):
        print("Getting agents in group:")
        group_id = input("Enter the group ID: ")
        status = input("Enter list of status of agents (active, pending, never_connected, disconnected), use comma to enter multiple statuses: ")
        url = f"{self.protocol}://{self.host}:{self.port}/groups/{group_id}/agents?pretty=true"

        params = {
            'limit': 500, 
            'status': status
        }

        response = requests.get(url, headers = self.requests_headers, params = params, verify = False)
        print(f"\nResponse:\n{response.text}")

    # Delete agents
    def delete_agents(self):
        print("Deleting agents:")
        agents_list = input("Enter a list of agent IDs (separated by comma) or 'all' to select all agents: ")
        status = input("Enter agent status (all, active, pending, never_connected, disconnected), separated by comma if multiple, leave blank for all status: ")
        if (status == ''): status = 'all'

        url = f"{self.protocol}://{self.host}:{self.port}/agents?pretty=true"

        params = {
            'agents_list': agents_list,
            'status': status,
            'older_than': '0s',
            'purge': True

        }

        response = requests.delete(url, headers=self.requests_headers, params=params, verify=False)
        print(f"\nResponse:\n{response.text}")

    # Create agent group ID
    def create_agent_group(self):
        print("Creating agent group:")
        group_id = input("Enter group ID (name): ")
        url = f"{self.protocol}://{self.host}:{self.port}/groups?pretty=true"

        payload_data = {
            "group_id": group_id
        }

        response = requests.post(url, headers=self.requests_headers, json=payload_data, verify=False)
        print(f"\nResponse:\n{response.text}")

    # Delete agent group ID
    def delete_agent_group(self):
        print("Deleting agent groups:")
        groups_list = input("Enter group IDs in a list, separate by comma: ")
        url = f"{self.protocol}://{self.host}:{self.port}/groups?pretty=true"

        params = {
            'groups_list': groups_list
        }

        response = requests.delete(url, headers=self.requests_headers, params=params, verify=False)
        print(f"\nResponse:\n{response.text}")

# Central command
def main(): 
    wazuh_api = WazuhManageAPI()
    while True:
        print("\n====================================================================")
        print("Choose an option:")
        print("1. List all agents")
        print("2. List all agent group IDs")
        print("3. Get agents status summary")
        print("4. List agents in a group")
        print("5. Delete agents")
        print("6. Add agent group")
        print("7. Delete agent group")
        print("0. Exit")

        choice = input("Enter the number of your choice: ")

        if choice == '1':
            wazuh_api.list_agents()
        elif choice == '2':
            wazuh_api.list_group_ids()
        elif choice == '3':
            wazuh_api.get_agents_status_summary()
        elif choice == '4':
            wazuh_api.get_agents_in_a_group()
        elif choice == '5':
            wazuh_api.delete_agents()
        elif choice == '6':
            wazuh_api.create_agent_group()
        elif choice == '7':
            wazuh_api.delete_agent_group()
        elif choice == '0':
            break
        else:
            print("Invalid choice. Please enter a valid option.")


if __name__ == "__main__":
    main()