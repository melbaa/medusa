# medusa

## What
This script finds the internal IP addresses of multiple AWS datastores and uses credentials supplied by you to connect from your local machine. The point is to avoid having to manually connect to a jump host to reach your data. The script also provides hints for datastore names, usernames and database names, generated from the supplied credentials.

The supported datastores are:
* Redshift
* RDS postgresql
* RDS mysql
* ElastiCache redis

## Requirements
The script assumes it has access to the internal IPs of the clusters/datastores, which means you have to be in the same VPN.

The script assumes you have configured awscli for your account. Also needs dig, psql (postgresql client), mysql (mysql client)

## Installation
Create a virtualenv with the libs in requirements.txt.

## Configuration
Create ~/.medusarc with entries like

```

settings:
  dns_servers:
    us_prod: 172.17.0.2

datastores:
  mysql-auxdb-example:
    aliases:
    - auxdb-example
    aws_identifier: prod-rds-auxdb-example
    aws_type: rds-mysql
    databases:
    - example
    users:
      admin: password

  postgres-portal-e:
    aliases:
    - portal-e
    aws_identifier: prod-rds-portal-e
    aws_type: rds-postgres
    databases:
    - example
    users:
      example: example


  redshift-example:
    aliases:
    - redshift-example
    - re
    aws_identifier: prod-redshift-example
    aws_type: redishft
    databases:
    - exampledb1
    - exampledb2
    users:
      user1: pass1
      user2: pass2

```

## Usage
medusa `<datastore name>` `<user name>` `<db name>`

medusa redshift-example user1 exampledb1
