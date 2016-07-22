#!/usr/bin/env python

"""
Unit tests for the EsuRestApi class
"""

import unittest, random, string, hashlib
from xml.etree.ElementTree import fromstring
from EsuRestApi import EsuRestApi, EsuException

class EsuRestApiTest(unittest.TestCase):
    
    # Enter your own host in the form of sub.domain.com or 10.0.1.250
    host = "lciga090.lss.emc.com"
    
    # Enter the port where Atmos lives here
    port = 80
    
    # Enter your full UID in the form of something/something_else
    uid = "0e2200283d4143d9b2895992a64cd319/test"
    
    # Enter your secret here.  (shhsh!)
    secret = "lYp88RptTEnBOEh/DC0w5ys7olU="
    
    def setUp(self):
        self.esu = EsuRestApi(self.host, self.port, self.uid, self.secret)
        self.oid_clean_up = []
        self.path_clean_up = []
    
    def tearDown(self):
        if self.oid_clean_up:
            for object in self.oid_clean_up:
                self.esu.delete_object(object)
        
        if self.path_clean_up:
            dir = self.path_clean_up[0].split("/")
            self.esu.delete_directory(dir[0])

    def test_create_empty_object(self):
        data = " "
        oid = self.esu.create_object(data=data)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        self.oid_clean_up.append(oid)
        
    def test_create_empty_object_on_path(self):
        data = " "
        path = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)) + "/file.data"
        oid = self.esu.create_object_on_path(data=data, path=path)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        self.oid_clean_up.append(oid)
        self.path_clean_up.append(path)
            
    def test_create_object_with_content(self):
        data = "The quick brown fox jumps over the lazy dog"
        oid = self.esu.create_object(data=data)
        object = self.esu.read_object(oid)
        self.assertEquals(data, object)
        self.oid_clean_up.append(oid)
    
    def test_create_object_with_content_and_checksum(self):
        data = "The quick brown fox jumps over the lazy dog"
        checksum = "SHA1/%d/%s" %  (len(data), hashlib.sha1(data).hexdigest())
        oid = self.esu.create_object(data=data, checksum=checksum)
        self.oid_clean_up.append(oid)
        object = self.esu.read_object(oid)
        self.assertEquals(data, object)
    
    def test_create_object_on_path_with_content(self):
        data = "The quick brown fox jumps over the lazy dog"
        path = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)) + "/file.data"
        oid = self.esu.create_object_on_path(data=data, path=path)
        self.oid_clean_up.append(oid)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
    
    def test_create_object_on_path_with_content_and_checksum(self):
        data = "The quick brown fox jumps over the lazy dog"
        path = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)) + "/file.data"
        checksum = "SHA1/%d/%s" %  (len(data), hashlib.sha1(data).hexdigest())
        oid = self.esu.create_object_on_path(data=data, path=path, checksum=checksum)
        self.oid_clean_up.append(oid)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
    
    def test_create_object_on_path_with_metadata(self):
        data = "The quick brown fox jumps over the lazy dog"
        listable_meta = {"key1" : "value1", "key2" : "value2", "key3" : "value3"}
        path = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)) + "/file.data"
        oid = self.esu.create_object_on_path(data=data, path=path, listable_meta=listable_meta)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        
        # Retrieves existing metadata for an object and compares it to the known metadata dictionary that was stored
        metadata = self.esu.get_user_metadata(oid)['listable_user_meta']
        self.assertEqual(listable_meta, metadata, "metadata key/values are wrong")
        
        self.oid_clean_up.append(oid)
        self.path_clean_up.append(path)
    
    def test_create_object_with_metadata(self):
        data = "The quick brown fox jumps over the lazy dog"
        listable_meta = {"key1" : "value1", "key2" : "value2", "key3" : "value3"}
        oid = self.esu.create_object(data=data, listable_meta=listable_meta)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        
        # Retrieves existing metadata for an object and compares it to the known metadata dictionary that was stored
        metadata = self.esu.get_user_metadata(oid)['listable_user_meta']
        self.assertEqual(listable_meta, metadata, "metadata key/values are wrong")
        
        self.oid_clean_up.append(oid)
    
    def test_read_acl(self):
        data = "The quick brown fox jumps over the lazy dog"
        oid = self.esu.create_object(data=data)
        uid = self.esu.uid.split("/")[0]
        user_acl = "%s=FULL_CONTROL" % uid
        resp = self.esu.set_acl(oid, user_acl)
        
        acl = self.esu.get_acl(oid)['user_acl'][uid]
        self.assertEqual(acl, "FULL_CONTROL", "acl does not match")
        
        self.oid_clean_up.append(oid)
    
    
    def test_delete_user_metadata(self):
        data = "The quick brown fox jumps over the lazy dog"
        listable_meta = {"key1" : "value1"}
        oid = self.esu.create_object(data=data, listable_meta=listable_meta)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        
        # Retrieves existing metadata for an object and compares it to the known metadata dictionary that was stored
        metadata = self.esu.get_user_metadata(oid)['listable_user_meta']
        self.assertEqual(listable_meta, metadata, "metadata key/values are wrong")
        
        self.esu.delete_user_metadata(object_id=oid, metadata_key="key1")
        metadata = self.esu.get_user_metadata(oid)['listable_user_meta']
        self.assertEqual(metadata, {})
        
        self.oid_clean_up.append(oid)
    
    def test_get_system_metadata(self):
        data = "The quick brown fox jumps over the lazy dog"
        oid = self.esu.create_object(data=data)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        system_meta = self.esu.get_system_metadata(oid)
        self.assertTrue(system_meta['size'], "Size should be > 0" )
        self.assertTrue(system_meta['ctime'], "the ctime was not set")
        self.assertEqual(system_meta['objectid'], oid, "Object IDs do not match")
        self.oid_clean_up.append(oid)
    
    def test_list_objects(self):
        data = "The quick brown fox jumps over the lazy dog"
        key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
        listable_meta = {key : "value1"}
        oid = self.esu.create_object(data=data, listable_meta=listable_meta)
        self.assertTrue(oid, "null object ID returned")
        object = self.esu.read_object(oid)
        self.assertEqual(object, data, "wrong object content")
        
        list = self.esu.list_objects(metadata_key=key)
        self.assertEqual(oid, list[0][0], "wrong object ids")
        self.oid_clean_up.append(oid)
        
    def test_list_directory(self):
        data = "The quick brown fox jumps over the lazy dog"
        path = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8)) + "/file.data"
        oid = self.esu.create_object_on_path(data=data, path=path)
        dir = path.split("/")[0]
        list = self.esu.list_directory(dir)
        self.assertEqual(oid, list[0][0][0], "wrong object ids")
        self.oid_clean_up.append(oid)
        self.path_clean_up.append(path)
        
    def test_delete_object(self):
        data = "The quick brown fox jumps over the lazy dog"
        oid = self.esu.create_object(data=data)
        self.assertTrue(oid, "null object ID returned")
        self.esu.delete_object(oid)
        
        try:
            object = self.esu.read_object(oid)
            
        except EsuException, e:
            self.assertEqual(e.atmos_error_code, "1003", "wrong error code")
        
if __name__ == "__main__":
    test_classes = [ EsuRestApiTest ]
    for test_class in test_classes:
        temp = str(test_class)
        name = temp.split('.')[-1][:-2]
        print "Start of test for", name
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        unittest.TextTestRunner(verbosity=2).run(suite)
        print "End of test for", name
    
