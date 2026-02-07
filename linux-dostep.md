# Dostęp do serwera linix

## Architektura rozwiązania

### 1. Tabela DynamoDB

```javascript
Table: StudentSSHAccess
PK: cognito_user_id (String) - np. "us-east-1:12345678-1234-1234-1234-123456789012"
Attributes:
- username (String) - np. "jan_kowalski" 
- public_key (String) - zawartość klucza publicznego SSH
- linux_username (String) - nazwa użytkownika w systemie Linux
- created_at (Number) - timestamp
- active (Boolean) - czy dostęp jest aktywny
```

### 2. Frontend - formularz dodania klucza

```html
<!-- Po zalogowaniu przez Cognito -->
<form id="ssh-key-form">
  <label>Wklej swój klucz publiczny SSH:</label>
  <textarea id="public-key" rows="5" cols="80" 
            placeholder="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."></textarea>
  <button type="submit">Aktywuj dostęp SSH</button>
</form>

<div id="instructions">
  <h3>Jak wygenerować klucz SSH?</h3>
  <p>W terminalu wykonaj:</p>
  <code>ssh-keygen -t rsa -b 4096 -C "twoj@email.com"</code>
  <p>Następnie skopiuj zawartość pliku:</p>
  <code>cat ~/.ssh/id_rsa.pub</code>
</div>
```

### 3. Backend - Lambda funkcja

```python
import boto3
import json
import paramiko
import re
from botocore.exceptions import ClientError

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('StudentSSHAccess')

def lambda_handler(event, context):
    # Pobierz dane użytkownika z Cognito
    cognito_user_id = event['requestContext']['authorizer']['claims']['sub']
    username = event['requestContext']['authorizer']['claims']['preferred_username']
    
    body = json.loads(event['body'])
    public_key = body['public_key'].strip()
    
    # Walidacja klucza publicznego
    if not validate_ssh_key(public_key):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Nieprawidłowy klucz publiczny SSH'})
        }
    
    # Generuj bezpieczną nazwę użytkownika Linux (tylko małe litery, cyfry, _)
    linux_username = re.sub(r'[^a-z0-9_]', '_', username.lower())
    linux_username = f"student_{linux_username}"
    
    # Zapisz do DynamoDB
    try:
        table.put_item(Item={
            'cognito_user_id': cognito_user_id,
            'username': username,
            'public_key': public_key,
            'linux_username': linux_username,
            'created_at': int(time.time()),
            'active': True
        })
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
    
    # Wywołaj funkcję provisionującą użytkownika na serwerze
    provision_user(linux_username, public_key)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Dostęp SSH aktywowany',
            'linux_username': linux_username,
            'server_address': 'training-server.example.com',
            'ssh_command': f'ssh {linux_username}@training-server.example.com'
        })
    }

def validate_ssh_key(key):
    """Sprawdza czy klucz ma prawidłowy format"""
    try:
        # Spróbuj sparsować klucz
        parts = key.split()
        if len(parts) < 2:
            return False
        if parts[0] not in ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256']:
            return False
        # Dodatkowa walidacja przez paramiko
        from io import StringIO
        key_file = StringIO(key)
        paramiko.RSAKey.from_string(parts[1])
        return True
    except:
        return False

def provision_user(linux_username, public_key):
    """Tworzy użytkownika i dodaje klucz SSH na serwerze Linux"""
    # Opcja A: Wywołaj SSM Run Command
    ssm = boto3.client('ssm')
    
    commands = [
        # Utwórz użytkownika jeśli nie istnieje
        f"id {linux_username} || useradd -m -s /bin/bash {linux_username}",
        # Utwórz katalog .ssh
        f"mkdir -p /home/{linux_username}/.ssh",
        # Dodaj klucz publiczny
        f"echo '{public_key}' > /home/{linux_username}/.ssh/authorized_keys",
        # Ustaw odpowiednie uprawnienia
        f"chmod 700 /home/{linux_username}/.ssh",
        f"chmod 600 /home/{linux_username}/.ssh/authorized_keys",
        f"chown -R {linux_username}:{linux_username} /home/{linux_username}/.ssh"
    ]
    
    response = ssm.send_command(
        InstanceIds=['i-your-instance-id'],  # ID Twojego serwera
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': commands}
    )
    
    return response
```

### 4. Skrypt pomocniczy na serwerze (alternatywa do SSM)

Jeśli wolisz podejście bez SSM, możesz umieścić skrypt na serwerze:

```bash
#!/bin/bash
# /opt/scripts/add_student.sh

LINUX_USERNAME=$1
PUBLIC_KEY=$2

# Utwórz użytkownika
id "$LINUX_USERNAME" || useradd -m -s /bin/bash "$LINUX_USERNAME"

# Konfiguruj SSH
mkdir -p /home/$LINUX_USERNAME/.ssh
echo "$PUBLIC_KEY" > /home/$LINUX_USERNAME/.ssh/authorized_keys
chmod 700 /home/$LINUX_USERNAME/.ssh
chmod 600 /home/$LINUX_USERNAME/.ssh/authorized_keys
chown -R $LINUX_USERNAME:$LINUX_USERNAME /home/$LINUX_USERNAME/.ssh

# Opcjonalnie: dodaj do grupy students
usermod -aG students "$LINUX_USERNAME"
```

Lambda wywołuje ten skrypt przez SSH:

```python
import paramiko

def provision_user(linux_username, public_key):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('your-server.com', username='admin', key_filename='/tmp/admin_key')
    
    cmd = f"/opt/scripts/add_student.sh '{linux_username}' '{public_key}'"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    ssh.close()
```

### 5. API Gateway setup

```yaml
/ssh/register:
  POST:
    authorizer: CognitoAuthorizer
    integration: Lambda (powyższa funkcja)
```

### 6. Bezpieczeństwo

Na serwerze Linux:

```bash
# Ogranicz możliwości studentów
nano /etc/ssh/sshd_config
```

```
# Dla grupy students
Match Group students
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    MaxSessions 2
```

```bash
# Ustaw limity zasobów
nano /etc/security/limits.conf
```

```
@students hard nproc 50
@students hard cpu 10
@students hard maxlogins 2
```

### 7. Czyszczenie po szkoleniu

Lambda do deaktywacji dostępu:

```python
def deactivate_student(cognito_user_id):
    # Oznacz jako nieaktywny w DynamoDB
    table.update_item(
        Key={'cognito_user_id': cognito_user_id},
        UpdateExpression='SET active = :val',
        ExpressionAttributeValues={':val': False}
    )
    
    # Opcjonalnie: usuń użytkownika z serwera
    # lub wyłącz konto: usermod -L username
```

Masz pytania odnośnie którejś części implementacji?