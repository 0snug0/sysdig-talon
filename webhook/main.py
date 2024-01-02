from flask import Flask, request, Response
import requests, json

sidekick_ip = '34.72.59.3'
sidekick_port = '2801'
sidekick_url = 'http://'+sidekick_ip+':'+sidekick_port

talon_ip = '34.171.132.116'
talon_port = '2803'
talon_url = 'http://'+talon_ip+':'+talon_port

# Sysdig Secure JSON Ouput format
sysdig_secure_data = [
    {
        "id": "17a69ae69f3620d461ba501b11da04b7",
        "timestamp": "2023-05-25T13:44:05.478445995Z",
        "category": "runtime",
        "source": "syscall",
        "name": "Sensitive Info Exfiltration",
        "description": "Web server accessing forbidden directory",
        "severity": 2,
        "actions": [],
        "content": {
            "fields": {
                "container.id": "ee97d9c4186f",
                "container.image.repository": "docker.io/library/alpine",
                "evt.time": 1685022245478445995,
                "k8s.ns.name": "default",
                "k8s.pod.name": "kubecon",
                "proc.cmdline": "sh -c clear; (bash || ash || sh)",
                "proc.name": "sh",
                "proc.pname": "runc",
                "proc.tty": 34816,
                "user.loginuid": -1,
                "user.name": "root"
            },
            "ruleName": "Outbound Connection to C2 Servers",
            "output": "A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=default k8s.pod=kubecon container=ee97d9c4186f shell=sh parent=runc cmdline=sh -c clear; (bash || ash || sh) terminal=34816 container_id=ee97d9c4186f image=docker.io/library/alpine)",
            "ruleTags": [
                "container",
                "mitre_execution",
                "shell"
            ]},
        "labels": {
            "aws.accountId": "845151661675",
            "aws.instanceId": "i-0ea769e3eb5e6e849",
            "aws.region": "us-east-1",
            "cloudProvider.account.id": "845151661675",
            "cloudProvider.name": "aws",
            "cloudProvider.region": "us-east-1",
            "container.image.digest": "sha256:74941e12721385c8f3d5b9438294eae9050087badfc8c4c9e67195d098e40e11",
            "container.image.id": "5e8b2f0509f4",
            "container.image.repo": "docker.io/sysdiglabs/workshop-forensics-1-phpping",
            "container.image.tag": "0.1",
            "container.label.io.kubernetes.container.name": "store-frontend-ping-php",
            "container.label.io.kubernetes.pod.name": "store-frontend-ping-php-6d99c8958-dvng2",
            "container.label.io.kubernetes.pod.namespace": "sensitive-info-exfiltration",
            "container.name": "store-frontend-ping-php",
            "host.hostName": "falco-xczjd",
            "host.mac": "02:0e:ec:d5:bc:a7",
            "kubernetes.cluster.name": "demo-kube-aws",
            "kubernetes.deployment.name": "store-frontend-ping-php",
            "kubernetes.namespace.name": "default",
            "kubernetes.node.name": "i-0ea769e3eb5e6e849",
            "kubernetes.pod.name": "ubuntu3-577cd75565-cs49p",
            "kubernetes.replicaSet.name": "store-frontend-ping-php-6d99c8958",
            "kubernetes.service.name": "php",
            "kubernetes.workload.name": "store-frontend-ping-php",
            "kubernetes.workload.type": "deployment",
            "process.name": "sh"
        }
    }]

# Example output of falco
'''
{
    "hostname": "falco-xczjd",
    "output": "13:44:05.478445995: Critical A shell was spawned in a container with an attached terminal (user=root user_loginuid=-1 k8s.ns=default k8s.pod=kubecon container=ee97d9c4186f shell=sh parent=runc cmdline=sh -c clear; (bash || ash || sh) terminal=34816 container_id=ee97d9c4186f image=docker.io/library/alpine)",
    "priority": "Critical",
    "rule": "Terminal shell in container",
    "source": "syscall",
    "tags": [
        "container",
        "mitre_execution",
        "shell"
    ],
    "time": "2023-05-25T13:44:05.478445995Z",
    "output_fields": {
        "container.id": "ee97d9c4186f",
        "container.image.repository": "docker.io/library/alpine",
        "evt.time": 1685022245478445995,
        "k8s.ns.name": "default",
        "k8s.pod.name": "kubecon",
        "proc.cmdline": "sh -c clear; (bash || ash || sh)",
        "proc.name": "sh",
        "proc.pname": "runc",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root"
    }
}
'''

def sev2prio(severity):
    prio = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug']
    return prio[severity]

falco_ts = sysdig_secure_data[0]['timestamp'].split('T')[1].rstrip('Z')

def map_data(sysdig_secure_data):
    label2fields = {
        "output_fields": {
            "k8s.ns.name": sysdig_secure_data[0]['labels']['kubernetes.namespace.name'],
            "k8s.pod.name": sysdig_secure_data[0]['labels']['kubernetes.pod.name'],
    }}
    sysdig_secure_data[0]['content']['fields'].update(label2fields['output_fields'])
    restructure = {
        "hostname": sysdig_secure_data[0]['labels']['host.hostName'],
        "output":  f'{falco_ts}: {sev2prio(sysdig_secure_data[0]["severity"])} {sysdig_secure_data[0]["content"]["output"]}',
        "priority": sev2prio(sysdig_secure_data[0]['severity']),
        "rule": sysdig_secure_data[0]['content']['ruleName'],
        "source": sysdig_secure_data[0]['source'],
        "tags": sysdig_secure_data[0]['content']['ruleTags'],
        "time": sysdig_secure_data[0]['timestamp'],
        "output_fields": sysdig_secure_data[0]['content']['fields']
    }
    return restructure

# print(json.dumps(map_data(sysdig_secure_data), indent=4))

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def respond():
    res = json.dumps(map_data(request.json), indent=4)
    r = requests.post(talon_url, data=res)
    print(r.status_code)

    print(res)
    return Response(response=res, status=200)

'''
curl 127.0.0.1:5000/webhook -H 'Content-Type: application/json' -d '[
        {
            "id": "17a683ab96a3b964df360850c6522a4a",
            "cursor": "PTE3YTY4M2FiOTZhM2I5NjRkZjM2MDg1MGM2NTIyYTRh",
            "timestamp": "2024-01-02T11:18:01.996269924Z",
            "customerId": 13314,
            "originator": "policy",
            "category": "runtime",
            "source": "syscall",
            "name": "Sensitive Info Exfiltration",
            "description": "Web server accessing forbidden directory",
            "severity": 0,
            "agentId": 2740954,
            "containerId": "f4d2da1ed561",
            "machineId": "02:0e:ec:d5:bc:a7",
            "actions": [
                {
                    "type": "capture",
                    "successful": true,
                    "token": "c4b31c08-48c8-4816-82f5-8413acecb8ef",
                    "afterEventNs": 15000000000,
                    "beforeEventNs": 10000000000
                }
            ],
            "content": {
                "falsePositive": false,
                "fields": {
                    "evt.category": "file",
                    "falco.rule": "Apache writing to non allowed directory",
                    "fd.name": "/tmp/passwd",
                    "proc.cmdline": "sh",
                    "proc.name": "sh",
                    "proc.pid": "3586141",
                    "proc.pname": "systemd",
                    "proc.ppid": "1",
                    "user.name": "www-data"
                },
                "internalRuleName": "Apache writing to non allowed directory",
                "matchedOnDefault": false,
                "origin": "Secure UI",
                "output": "Writig to forbidden directory (user=www-data command=sh file=/tmp/passwd) extra fields = (file 1 systemd 3586141 sh )",
                "policyId": 10152241,
                "ruleName": "Apache writing to non allowed directory",
                "ruleSubType": 0,
                "ruleTags": [
                    "filesystem"
                ],
                "ruleType": 6
            },
            "labels": {
                "aws.accountId": "845151661675",
                "aws.instanceId": "i-0ea769e3eb5e6e849",
                "aws.region": "us-east-1",
                "cloudProvider.account.id": "845151661675",
                "cloudProvider.name": "aws",
                "cloudProvider.region": "us-east-1",
                "container.image.digest": "sha256:74941e12721385c8f3d5b9438294eae9050087badfc8c4c9e67195d098e40e11",
                "container.image.id": "5e8b2f0509f4",
                "container.image.repo": "docker.io/sysdiglabs/workshop-forensics-1-phpping",
                "container.image.tag": "0.1",
                "container.label.io.kubernetes.container.name": "store-frontend-ping-php",
                "container.label.io.kubernetes.pod.name": "store-frontend-ping-php-6d99c8958-dvng2",
                "container.label.io.kubernetes.pod.namespace": "sensitive-info-exfiltration",
                "container.name": "store-frontend-ping-php",
                "host.hostName": "i-0ea769e3eb5e6e849",
                "host.mac": "02:0e:ec:d5:bc:a7",
                "kubernetes.cluster.name": "demo-kube-aws",
                "kubernetes.deployment.name": "store-frontend-ping-php",
                "kubernetes.namespace.name": "sensitive-info-exfiltration",
                "kubernetes.node.name": "i-0ea769e3eb5e6e849",
                "kubernetes.pod.name": "store-frontend-ping-php-6d99c8958-dvng2",
                "kubernetes.replicaSet.name": "store-frontend-ping-php-6d99c8958",
                "kubernetes.service.name": "php",
                "kubernetes.workload.name": "store-frontend-ping-php",
                "kubernetes.workload.type": "deployment",
                "process.name": "sh"
            }
        }
    ]'
'''
