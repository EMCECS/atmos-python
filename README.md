---------------------------------
| Python REST API for EMC Atmos |
---------------------------------

This API allows Python developers to easily connect to EMC Atmos.  It handles 
all of the low-level tasks such as generating and signing
requests, connecting to the server, and parsing server responses.  

Requirements
------------
 * Python 2.7 


Usage
------------

For basic calls to Atmos, you should add the following line to your Python code:

from EsuRestApi import EsuRestApi

------------

In order to use the API, you need to construct an instance of the EsuRestApi
class.  This class contains the parameters used to connect to the server.

api = EsuRestApi( host, port, uid, secret )

Where host is the hostname or IP address of an Atmos node that you're authorized
to access, port is the IP port number used to connect to the server (generally
80 for HTTP), UID is the username to connect as, and the secret is the
shared secret key assigned to the UID you're using.  The UID and shared secret
are available from your Atmos tenant administrator.  The secret key should be
a base-64 encoded string as shown in the tennant administration console, e.g
"jINDh7tV/jkry7o9D+YmauupIQk=".

After you have created your EsuRestApi object, you can use the methods on the
object to manipulate data in the cloud.  For instance, to create a new, empty
object in the cloud, you can simply call:

object_id = api.create_object(data = " ")

The create_object method will return an object_id that can be used in subsequent calls
to read the object, add metadata, etc.


TODO:

1.  Add support for versioning objects.
2.  Add support for checksums.
3.  Add support for ACLs.