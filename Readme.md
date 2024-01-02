# Sysdig Secure Talon Bridge
## POC: Sysdig Secure Talon Bridge

A webhook bridge to connect sysdig secure webhook actions to Talon

### Configure and Deploy Talon

You can use the default rules, just deploy with helm
BEWARE - There are destructive actions here
```
helm install -f falco-talon/helm/values.yaml falco-talon falco-talon/helm
```

Modify the rules found in `falco-talon/rules.yaml`

### Deploy webhook

WARNING: The webhook uses LoadBalancer service type, which means that it will be a publically accessiable endpoint
TODO: Use agent local forwarding
TODO: Add Secret Headers

```
kubectl create -f webhook/deployment.yaml
kubectl expose deployment webhook --port 80 --type LoadBalancer
```
![Alt text](<inaction.gif>)