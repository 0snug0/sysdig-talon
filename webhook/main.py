from flask import Flask, request, Response
import requests, json

## optional use side kick
# sidekick_ip = 'falco-sidekick'
# sidekick_port = '2801'
# sidekick_url = 'http://'+sidekick_ip+':'+sidekick_port

talon_ip = 'falco-talon'
talon_port = '2803'
talon_url = 'http://'+talon_ip+':'+talon_port


def sev2prio(severity):
    prio = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug']
    return prio[severity]


def map_data(sysdig_secure_data):
    falco_ts = sysdig_secure_data[0]['timestampRFC3339Nano'].split('T')[1].rstrip('Z')

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
        "time": sysdig_secure_data[0]['timestampRFC3339Nano'],
        "output_fields": sysdig_secure_data[0]['content']['fields']
    }
    return restructure


app = Flask(__name__)

@app.route('/', methods=['POST'])
def respond():
    req = request.json
    print(req)
    
    # When integrating a new webhook, you must test, and it must pass
    try:
        if req[0]['message'] == 'Hi from Sysdig!':
            res = json.dumps(req)
            return Response(response=res, status=200)
    except:
        pass

    # Map the required data
    try:
        res = json.dumps(map_data(request.json), indent=4)
    except Exception as e:
        print(f'ERROR: {e}')
        return Response(response='Error', status=500)
    
    # Send to Talon
    try:
        r = requests.post(talon_url, data=res)
        print(r.status_code)
    except Exception as e:
        print(f'ERROR: {e}')
        return Response(response='Error', status=500)
    
    print(f'INFO: {res}')
    return Response(response=res, status=200)