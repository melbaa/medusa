import pytest

import melbalabs.medusa.medusa as medusa

def test_redis():
    # control-dev single node
    # product replication group
    # control-redis clustered
    with pytest.raises(medusa.NotPrivateIpError):
        medusa.main(argv=['test', 'redis-control-dev', '0', '0001'])
    medusa.main(argv=['test', 'redis-control-redis', '0', '0001'])
    medusa.main(argv=['test', 'redis-product', '0', '0001'])
