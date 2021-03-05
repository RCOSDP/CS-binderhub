# config file for testing with minikube-config.yaml
import subprocess
try:
    minikube_ip = subprocess.check_output(['minikube', 'ip']).decode('utf-8').strip()
except (subprocess.SubprocessError, FileNotFoundError):
    minikube_ip = '192.168.1.100'

c.BinderHub.hub_url = 'http://{}:30123'.format(minikube_ip)
c.BinderHub.hub_api_token = 'aec7d32df938c0f55e54f09244a350cb29ea612907ed4f07be13d9553d18a8e4'
c.BinderHub.use_registry = False
c.BinderHub.build_namespace = 'binder-test'

c.BinderHub.oauth2_provider_enabled = True

c.BinderHub.oauth_db_url = 'sqlite:///binderhub-oauth.sqlite'
c.BinderHub.oauth_clients = [{'client_id': 'AAAA',
                              'client_secret': 'BBBB',
                              'redirect_uri': 'http://192.168.168.167:5000/project/binderhub/callback',
                              'description': 'Some Client'}]
c.BinderHub.oauth_no_confirm_list = ['AAAA']
