#!/usr/bin/env python
import hmac, base64, hashlib, time
import urllib2, urllib, httplib
import re, urlparse
from xml.etree.ElementTree import fromstring

from xml.dom.minidom import parse, parse

DEBUG = False
SIMULATE = False

class EsuRestApi(object):
 
    ID_EXTRACTOR = "/[0-9a-zA-Z]+/objects/([0-9a-f]{44})"
 
    def __init__(self, host, port, uid, secret):
        """ Constructor that sets up the URL and appropriate credentials used to sign HTTP requests """
        
        self.host, self.port, self.uid, self.secret = host, port, uid, secret
         
        if self.port == 443:
            self.scheme, self.netloc, self.path, self.params, self.query, self.fragment = "https", host, '', '', '', ''
            self.urlparts = (self.scheme, self.netloc, self.path, self.params, self.query, self.fragment)
            self.url = urlparse.urlunparse(self.urlparts)
        else:
            self.scheme, self.netloc, self.path, self.params, self.query, self.fragment = "http", host + ":" + str(port), '', '', '', ''
            self.urlparts = (self.scheme, self.netloc, self.path, self.params, self.query, self.fragment)
            self.url = urlparse.urlunparse(self.urlparts)
 
  
    def create_object(self, data = "", user_acl = None, listable_meta = None, non_listable_meta = None, mime_type = None, checksum = None, group_acl = None):
        """ Creates an object in the object interface and returns an object_id.
        
        Keyword arguments:
        listable_meta -- a dictionary containing key/value pairs. Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} (default None)
        non_listable_meta -- a dictionary containing key/value pairs. Ex. {"nl_key1/patriots" : "value", "nl_key2" : "value2", "nl_key3" : "value3"} (default None)
        data -- the object data itself, must not be empty
        
        """
        
        if mime_type == None and data != None:
            mime_type = "application/octet-stream"
         
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "POST\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects\n"
        headers += "x-emc-date:"+now+"\n"
     
        request = RequestWithMethod("POST", self.url+"/rest/objects")
     
        request.add_header("content-type", mime_type)
        request.add_data(data)

        if group_acl:
            headers += "x-emc-groupacl:" + group_acl + "\n"
            request.add_header('x-emc-groupacl', group_acl)
        
        if listable_meta:
            meta_string = self.__process_metadata(listable_meta)
            headers += "x-emc-listable-meta:"+meta_string+"\n"
            request.add_header("x-emc-listable-meta", meta_string)
            
        if non_listable_meta:
            nl_meta_string = self.__process_metadata(non_listable_meta)
            headers += "x-emc-meta:"+nl_meta_string+"\n"
            request.add_header("x-emc-meta", nl_meta_string)
            
        headers += "x-emc-uid:"+self.uid

        if user_acl:
            headers += "\nx-emc-useracl:"+user_acl
            request.add_header("x-emc-useracl", user_acl)

        if checksum:
            headers += "\nx-emc-wschecksum:" + checksum
            request.add_header("x-emc-wschecksum", checksum)
            
            
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
             
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            if e.code == 201:
                object_id = self.__parse_location(e)
                return object_id
            else:
                error_message = e.read()
                atmos_error = self.__parse_atmos_error(error_message)
                raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   # If there was no HTTPError, parse the location header in the response body to get the object_id  
            object_id = self.__parse_location(response)
            return object_id
    
    def create_object_on_path(self, path, user_acl = None, listable_meta = None, non_listable_meta = None, mime_type = None, data = "", group_acl = None, checksum=None):
        """ Creates an object in the namespace interface and returns an object_id.
        
        Keyword arguments:
        path -- the path in the namespace where the object should be created.  Non-existent directories will be automatically created.  
        listable_meta -- a dictionary containing key/value pairs. Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} (default None)
        non_listable_meta -- a dictionary containing key/value pairs. Ex. {"nl_key1/patriots" : "value", "nl_key2" : "value2", "nl_key3" : "value3"} (default None)
        data -- the object data itself, must not be empty
        
        """

        if path[0] != "/":
            path = "/" + path
     
        if mime_type == None:
            mime_type = "application/octet-stream"
         
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "POST\n" 
        request = RequestWithMethod("POST", self.url+"/rest/namespace"+urllib.quote(path))

        headers += mime_type+"\n"
        request.add_header("content-type", mime_type)
     
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/namespace"+str.lower(path)+"\n"
        headers += "x-emc-date:"+now+"\n"

        if group_acl:
            headers += "x-emc-groupacl:" + group_acl + "\n"
            request.add_header('x-emc-groupacl', group_acl)
    
        if listable_meta:
            meta_string = self.__process_metadata(listable_meta)
            headers += "x-emc-listable-meta:"+meta_string+"\n"
            request.add_header("x-emc-listable-meta", meta_string)
            
        if non_listable_meta:
            nl_meta_string = self.__process_metadata(non_listable_meta)
            headers += "x-emc-meta:"+nl_meta_string+"\n"
            request.add_header("x-emc-meta", nl_meta_string)
        
        headers += "x-emc-uid:"+self.uid

        if user_acl:
            headers += "\nx-emc-useracl:"+user_acl
            request.add_header("x-emc-useracl", user_acl)

        if checksum:
            headers += "\nx-emc-wschecksum:" + checksum
            request.add_header("x-emc-wschecksum", checksum)
     
        request = self.__add_headers(request, now)
        request.add_data(data)
         
        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            if e.code == 201:     
                object_id = self.__parse_location(e)
                return object_id
            
            else:
                error_message = e.read()
                atmos_error = self.__parse_atmos_error(error_message)
                raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   # If there was no HTTPError, parse the location header in the response body to get the object_id
            object_id = self.__parse_location(response)
            return object_id
  
    def list_objects(self, metadata_key, include_meta = False, filter_user_tags = None):
        """ Takes a listable metadata key and returns a list of objects that match.
        
        Keyword arguments:
        metadata_key -- the Atmos key portion of the key/value pair
        include_meta -- optionally returns an object list with system and user metadata (default False)

        """
        
        if metadata_key[0] == "/":
            metadata_key = metadata_key[1:]
            
        mime_type = "application/octet-stream"
         
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        request = urllib2.Request(self.url+"/rest/objects")
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects"+"\n"
        headers += "x-emc-date:"+now+"\n"
        
        if include_meta:
            headers += "x-emc-include-meta:"+str(1)+"\n"
            request.add_header("x-emc-include-meta", str(1))

        headers += "x-emc-tags:"+metadata_key+"\n"
        
        if filter_user_tags:
            headers += "x-emc-uid:"+self.uid+"\n"
            headers += "x-emc-user-tags:"+filter_user_tags
            request.add_header("x-emc-user-tags", filter_user_tags)
        
        else:
            headers += "x-emc-uid:"+self.uid
    
    
        request.add_header("content-type", mime_type)
        request.add_header("x-emc-tags", metadata_key)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:
            object_list = response.read()
            
            parsed_list = self.__parse_list_objects_response(object_list, include_meta = include_meta)
            
            if response.info().getheader('x-emc-token'):
                token = response.info().getheader('x-emc-token')    
                return parsed_list, token,
            
            return parsed_list, None,
    
    def list_directory(self, path, limit = None, include_meta = False, token = None, filter_user_tags = None):
        """ Lists objects in the namespace based on path
        
        Keyword arguments:
        path -- the path used to generate a list of objects
        
        """
        request = urllib2.Request(self.url+"/rest/namespace"+urllib.quote(path))

        mime_type = "application/octet-stream"
         
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n" 
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/namespace"+str.lower(path)+"\n"
        headers += "x-emc-date:"+now+"\n"
        
        if include_meta:
            headers += "x-emc-include-meta:"+str(1)+"\n"
            request.add_header("x-emc-include-meta", str(1))
        
        if limit:
            headers += "x-emc-limit:"+str(limit)+"\n"
            request.add_header('x-emc-limit', limit)
            
        if token:
            headers += "x-emc-token:" + token + "\n"
            request.add_header('x-emc-token', token)
            
            
        if filter_user_tags:
            headers += "x-emc-uid:"+self.uid+"\n"
            headers += "x-emc-user-tags:"+filter_user_tags
            request.add_header("x-emc-user-tags", filter_user_tags)
        
        else:
            headers += "x-emc-uid:"+self.uid

        
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:
            
            dir_list = response.read()
            
            parsed_list = self.__parse_list_directory_response(dir_list, include_meta = include_meta)
 
            if response.info().getheader('x-emc-token'):
                token = response.info().getheader('x-emc-token')    
                return parsed_list, token,
                
            else:    
                return parsed_list, None,
      
    def delete_object(self, object_id):
        """ Deletes objects based on object_id. """
      
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "DELETE\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = RequestWithMethod("DELETE", "%s/%s" % (self.url+"/rest/objects", object_id))
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)
        
        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)

        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   
            return response.getcode()


    def delete_directory(self, path):
        """ Deletes empty directories. """
      
        if path[0] != "/":
            path = "/" + path
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "DELETE\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/namespace/"+str.lower(path)+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = RequestWithMethod("DELETE", "%s/%s" % (self.url+"/rest/namespace", urllib.quote(path)))
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)
        
        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)

        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   # If there was no HTTPError, parse the location header in the response body to get the object_id
            return response.getcode()
        
      
    def read_object(self, object_id, extent = None, head = False):
        """  Returns an entire object or a partial object based on a byte range.
        
        Keyword arguments:
        object_id -- the object ID of the object to be read
        extent -- a byte range used to read portions of an object.  Not setting the extent returns the entire object (Default None)
        
        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        
        if head:
            request = RequestWithMethod("HEAD", "%s/%s" % (self.url+"/rest/objects", object_id))
            headers = "HEAD\n"
        else:
            request = urllib2.Request(self.url+"/rest/objects/"+object_id)
            headers = "GET\n"
            
        headers += mime_type+"\n"
        
        if extent:
            headers += "Bytes="+extent+"\n"
            request.add_header("Range", "Bytes="+extent)
        else:
            headers += "\n"

        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:
            if not SIMULATE:
                if head:
                    group_acl = {}
                    user_acl = {}
                    system_meta = {}
                    policy = {}
                
                    if response.info().getheader('x-emc-groupacl'):
                        group_acl = response.info().getheader('x-emc-groupacl')
                        group_acl = dict(u.split("=") for u in group_acl.split(", "))                              # Create a Python dictionary of the data in the header and return it.
                
                    if  response.info().getheader('x-emc-user-acl'):
                        user_acl = response.info().getheader('x-emc-user-acl')
                        user_acl = dict(u.split("=") for u in user_acl.split(", "))
                        
                    if  response.info().getheader('x-emc-meta'):
                        system_meta = response.info().getheader('x-emc-meta')
                        system_meta = dict(u.split("=") for u in system_meta.split(", "))
                        
                    if  response.info().getheader('x-emc-policy'):
                        policy = response.info().getheader('x-emc-policy')
                
                    return {"group_acl" : group_acl , "user_acl" : user_acl, "system_meta" : system_meta, "policy" : policy}    
           
                else:
                    body = response.read()
                    return body
                
    def read_object_from_path(self, path, extent = None, head = False):
        """  Returns an entire object or a partial object based on a byte range from the namespace interface.
        
        Keyword arguments:
        path -- the complete path to the object to be read
        extent -- a byte range used to read portions of an object.  Not setting the extent returns the entire object (Default None)
        
        """
        
        if path[0] == "/":
            path = path[1:]
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        
        
        if head:
            request = RequestWithMethod("HEAD", "%s/%s" % (self.url+"/rest/namespace",urllib.quote(path)))
            headers = "HEAD\n"

        else:
            request = urllib2.Request(self.url+"/rest/namespace/"+urllib.quote(path))
            headers = "GET\n"
            
        headers += mime_type+"\n"
        
        if extent:
            headers += "Bytes="+extent+"\n"
            request.add_header("Range", "Bytes="+extent)
        else:
            headers += "\n"

        headers += now+"\n"
        headers += "/rest/namespace/"+str.lower(path)+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:
            
            if not SIMULATE:
                if head:
                    group_acl = {}
                    user_acl = {}
                    system_meta = {}
                    policy = {}
                
                    if response.info().getheader('x-emc-groupacl'):
                        group_acl = response.info().getheader('x-emc-groupacl')
                        group_acl = dict(u.split("=") for u in group_acl.split(","))                              # Create a Python dictionary of the data in the header and return it.
                
                    if  response.info().getheader('x-emc-user-acl'):
                        user_acl = response.info().getheader('x-emc-user-acl')
                        user_acl = dict(u.split("=") for u in user_acl.split(","))
                        
                    if  response.info().getheader('x-emc-meta'):
                        system_meta = response.info().getheader('x-emc-meta')
                        system_meta = dict(u.split("=") for u in system_meta.split(", "))
                        
                    if  response.info().getheader('x-emc-policy'):
                        policy = response.info().getheader('x-emc-policy')
                
                    return {"group_acl" : group_acl , "user_acl" : user_acl, "system_meta" : system_meta, "policy" : policy}    
           
                else:
                    body = response.read()
                    return body
    
    def update_object(self, object_id, data, extent = None, listable_meta = None, non_listable_meta = None, mime_type = None):
        """ Updates an existing object with listable metadata, non-listable metadata, and/or bytes of actual object data based on range.
        If the extent parameter is excluded and data is set to an empty string the object will be overwritten with an empty object.  If the extent
        parameter is excluded and the data parameter contains data the entire object is overwritten with new contents.
        
        Keyword arguments:
        object_id -- the object to update 
        extent -- the portion of the object to modify (default None)
        listable_meta -- a dictionary containing key/value pairs Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} (default None)
        non_listable_meta -- a dictionary containing key/value pairs {"nl_key1/patriots" : "value", "nl_key2" : "value2", "nl_key3" : "value3"} (default None)
        data -- actual or partial object content.

        """
    
        mime_type = "application/octet-stream" 
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        request = RequestWithMethod("PUT", "%s/%s" % (self.url+"/rest/objects", object_id))
        
        headers = "PUT\n"
        headers += mime_type+"\n"
        
        if extent:
            headers += "Bytes="+extent
            request.add_header("Range", "Bytes="+extent)
                                                         
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"\n"
        headers += "x-emc-date:"+now+"\n"
     
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)
        request.add_data(data)
            
        if listable_meta:
            meta_string = self.__process_metadata(listable_meta)
            headers += "x-emc-listable-meta:"+meta_string+"\n"
            request.add_header("x-emc-listable-meta", meta_string)
            
        if non_listable_meta:
            nl_meta_string = self.__process_metadata(non_listable_meta)
            headers += "x-emc-meta:"+nl_meta_string+"\n"
            request.add_header("x-emc-meta", nl_meta_string)
     
        headers += "x-emc-uid:"+self.uid

        #print "String to Sign: " + headers
    
        hashout = self.__sign(headers)
     
        try:
            response = self.__send_request(request, hashout, headers)
        
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        
    def get_shareable_url(self, expiration, object_id = None, path = None):
        """ Generates a pre-signed URL that is accessible to non-Atmos users
        
        Keyword arguments:
        object_id -- the object to which you want to provide access
        path -- the full path to the object to which you want to create the shareable URL
        expiration -- Epoch time in the future that determines how long a shareable URL is valid
        
        """
        
        if path and path[0] == "/":
            path = path[1:]
        
        if object_id and path:
            raise Exception("both object_id and path parameters cannot be set simultaneously")
        
        if object_id == None and path == None:
            raise Exception("at least one of the parameters, object_id or path, need to be set")
        
        uid_dict = {}
        uid_dict["uid"] = self.uid
        encoded_uid = urllib.urlencode(uid_dict)
            
        sb = "GET\n"
        
        if object_id:
            sb += "/rest/objects/"+str(object_id)+"\n"
            resource = "/rest/objects/"+str(object_id)
        
        if path:
            sb += "/rest/namespace/"+str.lower(path)+"\n"
            path = urllib.quote(path)
            resource = "/rest/namespace/"+path
                      
        sb += self.uid+"\n"
        sb += str(expiration)
               
        signature = self.__sign(sb)
        sig_dict = {}
        sig_dict["signature"] = signature
        encoded_sig = urllib.urlencode(sig_dict)
                       
        resource += "?" + encoded_uid + "&expires=" + str(expiration) + "&" + encoded_sig
        url = self.scheme + "://" + self.host + resource
               
        return url
      
    
    def create_directory(self, path, user_acl=None, group_acl=None):
        """ Creates a directory in the namespace interface.  Returns an object_id.
        
        Keyword arguments:
        path -- directory path with no leading slash
        
        """
    
        if path[-1] != "/":                                                                                 # Add a slash at the end if they didn't include one
            path += "/"
            
        if path[0] == "/":
            path = path[1:]
            
        
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        content_type = "application/x-www-form-urlencoded" # Required by POST on some systems and by HTTP spec

        request = RequestWithMethod("POST", "%s/%s" % (self.url+"/rest/namespace", urllib.quote(path)))
        request = self.__add_headers(request, now)

        request.add_header('content-type', content_type)
    
        headers = "POST\n"
        headers += content_type + "\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/namespace/"+str.lower(path)+"\n"
        headers += "x-emc-date:"+now+"\n"

        if group_acl:
            headers += "x-emc-groupacl:" + group_acl + "\n"
            request.add_header('x-emc-groupacl', group_acl)

        headers += "x-emc-uid:"+self.uid

        if user_acl:
            headers += "\nx-emc-useracl:" + user_acl 
            request.add_header('x-emc-useracl', user_acl)

    
        #print 'String to Sign: ' + headers + "\n"

        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)

        except urllib2.HTTPError, e:
            if e.code == 201:
                
                object_id = self.__parse_location(e)
                return object_id
                
                return object_id
            else:
                error_message = e.read()
                atmos_error = self.__parse_atmos_error(error_message)
                raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   # If there was no HTTPError, parse the location header in the response body to get the object_id
            object_id = self.__parse_location(response)
            return object_id

    # Renames won't work before Atmos 1.3.x
    def rename_object(self, source, destination, force):
        """  Renames an object in the namespace interface.
        
        Keyword arguments:
        
        source -- The source path to the object Ex. path/to/object/foo.doc
        destination -- The destination path to the object Ex. path/to/object/bar.doc
        force -- If set to True, forces a rename
        
        """
      
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "POST\n"
        headers += "\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/namespace/"+str.lower(source)+"?rename"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-path:"+str.lower(destination)+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = RequestWithMethod("POST", "%s/%s" % (self.url+"/rest/namespace", source+"?rename"))
        request.add_header("x-emc-path", destination)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)

        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                                                  
            return response

    def set_user_metadata(self, object_id, listable_meta = None, non_listable_meta = None):
        """ Updates an existing object with listable and/or non-listable user metadata
        
        Keyword arguments:
        
        object_id -- The object ID of the object that should be updated with user metadata
        listable_meta -- a dictionary containing key/value pairs Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} (default None)
        non_listable_meta -- a dictionary containing key/value pairs {"nl_key1/patriots" : "value", "nl_key2" : "value2", "nl_key3" : "value3"} (default None)
        
        """
        
        mime_type = "application/octet-stream" 
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "POST\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?metadata/user"+"\n"
        headers += "x-emc-date:"+now+"\n"
     
        request = RequestWithMethod("POST", "%s/%s" % (self.url+"/rest/objects", object_id+"?metadata/user"))
        request.add_header("content-type", mime_type) 
        request = self.__add_headers(request, now)
  
        if listable_meta:
            meta_string = self.__process_metadata(listable_meta)
            headers += "x-emc-listable-meta:"+meta_string+"\n"
            request.add_header("x-emc-listable-meta", meta_string)
            
        if non_listable_meta:
            nl_meta_string = self.__process_metadata(non_listable_meta)
            headers += "x-emc-meta:"+nl_meta_string+"\n"
            request.add_header("x-emc-meta", nl_meta_string)
     
        headers += "x-emc-uid:"+self.uid
        
        hashout = self.__sign(headers)
     
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
        
    def set_acl(self, object_id, user_acl):
        """ Updates an existing object with the specified ACL
        
        Keyword arguments:
        
        object_id -- The object ID of the object that should be updated with user metadata
        user_acl -- The key/value pair of the ACL to use to set on the object
        
        """
        
        mime_type = "application/octet-stream" 
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "POST\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?acl"+"\n"
        headers += "x-emc-date:"+now+"\n"
     
        request = RequestWithMethod("POST", "%s/%s" % (self.url+"/rest/objects", object_id+"?acl"))
        request.add_header("content-type", mime_type) 
        request = self.__add_headers(request, now)
        
        headers += "x-emc-uid:"+self.uid+"\n"
        headers += "x-emc-useracl:"+user_acl
        request.add_header("x-emc-useracl", user_acl)
        
        hashout = self.__sign(headers)
     
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)

    def get_acl(self, object_id):                                                                     
        """ Returns listable and/or non-listable user metadata in the form of a Python dictionary ( Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} )
        based on object_id.  Returns one or more empty dictionaries if no metadata exists.
        
        Keyword arguments:
        object_id -- The object ID of the object whose metadata should be returned 
        
        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?acl"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = urllib2.Request(self.url+"/rest/objects/"+object_id+"?acl")
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
        
        else:                                                                       
            if not SIMULATE:
                user_acl = {}
                
                if response.info().getheader('x-emc-useracl'):
                    user_acl = response.info().getheader('x-emc-useracl')
                    user_acl = dict(u.split("=") for u in user_acl.split(", "))                              # Create a Python dictionary of the data in the header and return it.
               
                return {"user_acl" : user_acl}

            
    def delete_user_metadata(self, object_id, metadata_key):
        """ Takes a listable metadata keys and returns a list of objects that match.
        
        Keyword arguments:
        object_id -- The object ID of the object whose metadata should be deleted
        metadata_key -- the key portion of the Atmos metadata key/value pair

        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "DELETE\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?metadata/user"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-tags:"+metadata_key+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = RequestWithMethod("DELETE", "%s/%s" % (self.url+"/rest/objects", object_id+"?metadata/user"))
        request.add_header("content-type", mime_type)
        request.add_header("x-emc-tags", metadata_key)
        
        request = self.__add_headers(request, now)
        
        hashout = self.__sign(headers)

        try:
            response = self.__send_request(request, hashout, headers)

        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   
            return response
        
        
    def get_user_metadata(self, object_id):                                                                     
        """ Returns listable and/or non-listable user metadata in the form of a Python dictionary ( Ex. {"key1 : "value", "key2" : "value2", "key3" : "value3"} )
        based on object_id.  Returns one or more empty dictionaries if no metadata exists.
        
        Keyword arguments:
        object_id -- The object ID of the object whose metadata should be returned 
        
        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?metadata/user"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = urllib2.Request(self.url+"/rest/objects/"+object_id+"?metadata/user")
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
        
        else:                                                                       
            if not SIMULATE:
                nl_user_meta = {}
                listable_user_meta = {}
                
                if response.info().getheader('x-emc-meta'):
                    nl_user_meta = response.info().getheader('x-emc-meta')
                    nl_user_meta = dict(u.split("=") for u in nl_user_meta.split(", "))                              # Create a Python dictionary of the data in the header and return it.
                
                if response.info().getheader('x-emc-listable-meta'):
                    listable_user_meta = response.info().getheader('x-emc-listable-meta')
                    listable_user_meta = dict(u.split("=") for u in listable_user_meta.split(", "))
                
                return {"listable_user_meta" : listable_user_meta , "nl_user_meta" : nl_user_meta}
    
    
    def get_system_metadata(self, object_id, sys_tags = None):                                                  
        """ Returns system metadata in the form of a Python dictionary based on object_id
        Optionally filter the results by passing in one or more system metadata tags
        
        Keyword arguments:  
        object_id -- The object ID of the object whose metadata should be returned 
        sys_tags -- List of system tags to be returned in the response Ex. (sys_tags = "atime,uid")
        
        """
        
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?metadata/system"+"\n"
        headers += "x-emc-date:"+now+"\n"

        request = urllib2.Request(self.url+"/rest/objects/"+object_id+"?metadata/system")
        
        if sys_tags:
            headers += "x-emc-tags:"+sys_tags+"\n"
            request.add_header("x-emc-tags", sys_tags)

        headers += "x-emc-uid:"+self.uid
    
        request.add_header("content-type", mime_type)        
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                   
            if not SIMULATE:
                system_meta = []
                system_meta = response.info().getheader('x-emc-meta')
                system_meta = dict(u.split("=") for u in system_meta.split(", "))                                    # Create a Python dictionary of the data in the header and return it.
                return system_meta
    
    def get_listable_tags(self, metadata_key = None):
        """ Returns all the top level listable keys for which the given UID has access to in their namespace.
        Takes an optional listable metadata key and returns a list of child keys.
        
        Keyword arguments:
        metadata_key -- the Atmos key portion of the key/value pair  (Default None)

        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects"+"?listabletags"+"\n"
        headers += "x-emc-date:"+now+"\n"
        
        request = urllib2.Request(self.url+"/rest/objects"+"?listabletags")

        if metadata_key:
            if metadata_key[0] == "/":
                metadata_key = metadata_key[1:]
            headers += "x-emc-tags:"+metadata_key+"\n"
            request.add_header("x-emc-tags", metadata_key)

        headers += "x-emc-uid:"+self.uid
    
        request.add_header("content-type", mime_type)
        
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
         
        else:                                                                                                   
            response = response.info().getheader('x-emc-listable-tags')
            listable_tags = response.split(', ')
            return listable_tags
    
    def get_object_info(self, object_id):
        """ Returns replica information for a given object.  Only works with Atmos 1.4 and later.
        
        Keyword arguments:
        object_id -- The object ID of the object whose relica information should be returned 
        
        """
        
        mime_type = "application/octet-stream"
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += mime_type+"\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/objects/"+object_id+"?info"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = urllib2.Request(self.url+"/rest/objects/"+object_id+"?info")
        request.add_header("content-type", mime_type)
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            error_message = e.read()
            atmos_error = self.__parse_atmos_error(error_message)
            raise EsuException(e.code, atmos_error)
        
        else:                                                                       
            body = response.read()
            
            object_info = self.__parse_object_info_response(body)
            
            return object_info
    
    
    def get_service_information(self):
        """ Returns Atmos version information. """
        
        now = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    
        headers = "GET\n"
        headers += "\n"
        headers += "\n"
        headers += now+"\n"
        headers += "/rest/service"+"\n"
        headers += "x-emc-date:"+now+"\n"
        headers += "x-emc-uid:"+self.uid
    
        request = urllib2.Request(self.url+"/rest/service")
        request = self.__add_headers(request, now)

        hashout = self.__sign(headers)
      
        try:
            response = self.__send_request(request, hashout, headers)
      
        except urllib2.HTTPError, e:
            if e.code == 500:
                return 500
            
            else:
                error_message = e.read()
                atmos_error = self.__parse_atmos_error(error_message)
                raise EsuException(e.code, atmos_error)
         
        else:
            body = response.read()
            
            version = self.__parse_version_information(body)
            
            return version
                   
    
    def __send_request(self, request, hashout, headers):
        # Private method to actually send the request
        
        headers += ("\nx-emc-signature:"+hashout)

        request.add_header("x-emc-signature", hashout)

        response = urllib2.urlopen(request)
        return response
    
    
    def __sign(self, headers):
        # Private method used to sign HTTP requests
        #print 'String to Sign:', headers
        
        decodedkey = base64.b64decode(self.secret)                                                          
        hash = hmac.new(decodedkey, headers, hashlib.sha1).digest()                                         
        hashout = base64.encodestring(hash).strip()                                                         
   
        return hashout
    
    
    def __process_metadata(self, metadata):                                                             
        # Private method used to strip more than one whitespace and process dictionary of key/value pairs into the string used in the HTTP request
        
        meta_string = ""
        for k,v in metadata.iteritems():
            meta_string += "%s=%s," % (k,v) 
        meta_string = meta_string[0:-1]                                                                         # Create a new string using a slice to remove the trailing comma                                                       
        meta_string = ' '.join(meta_string.split())                                                             # Remove two or more spaces if they exist
        
        return meta_string
    
    def __add_headers(self, request, now):
        
        request.add_header("date", now)
        #request.add_header("host", self.host)
        request.add_header("x-emc-date", now)
        request.add_header("x-emc-uid", self.uid)
        
        return request
    
    def __parse_location(self, response):
            location = response.info().getheader('location')
            search = re.search(self.ID_EXTRACTOR, location)
            reg = search.groups() 
            object_id = reg[0]
            return object_id
        
    def __parse_atmos_error(self, error):
        tree = fromstring(error)
        self.code = tree.find("Code")
        self.message = tree.find("Message")
        return self


    def __parse_list_objects_response(self, list, include_meta):
        tree = fromstring(list)
        NS = "{http://www.emc.com/cos/}"
        
        if include_meta:

            parsed_list = []
            object_dictionary = {}
            
            for object in tree.iter(NS + "Object"):
                for oid in object.iter(NS + "ObjectID"):
                    for sys_metadata_list in object.iter(NS + "SystemMetadataList"):
                        for sys_meta in sys_metadata_list.iter(NS + "Metadata"):
                            if oid.text not in object_dictionary:
                                object_dictionary[oid.text] = {}
                                object_dictionary[oid.text]['system_metadata'] = {}
                                object_dictionary[oid.text]['system_metadata'] = []
                                object_dictionary[oid.text]['user_metadata'] = {}
                            
                            object_dictionary[oid.text]['system_metadata'].append((sys_meta[0].text, sys_meta[1].text, "False"))
                            
                            object_dictionary[oid.text]['user_metadata'] = [] 
                            for user_metadata_list in object.iter(NS + "UserMetadataList"):
                                for user_meta in user_metadata_list.iter(NS + "Metadata"):
                                    
                                    object_dictionary[oid.text]['user_metadata'].append((user_meta[0].text, user_meta[1].text, user_meta[2].text))
                            
                            
            parsed_list.append(object_dictionary)

        else:
            parsed_list = []
            for object in tree.iter(NS + "Object"):
                    for oid in object.iter(NS + "ObjectID"):
                        parsed_list.append(oid.text)
        
        return parsed_list
    
    def __parse_list_directory_response(self, list, include_meta):
        tree = fromstring(list)
        NS = "{http://www.emc.com/cos/}"
        
        if include_meta:

            parsed_list = []
            object_dictionary = {}
            
            for list in tree.iter(NS + "DirectoryList"):
                for object in list.iter(NS + "DirectoryEntry"):
                    for sys_metadata_list in object.iter(NS + "SystemMetadataList"):
                        for sys_meta in sys_metadata_list.iter(NS + "Metadata"):
                            if object[2].text not in object_dictionary:
                                object_dictionary[object[2].text] = {}
                                object_dictionary[object[2].text]['system_metadata'] = {}
                                object_dictionary[object[2].text]['system_metadata'] = []
                                object_dictionary[object[2].text]['user_metadata'] = {}
                            
                            object_dictionary[object[2].text]['system_metadata'].append((sys_meta[0].text, sys_meta[1].text, "false"))
                            
                            object_dictionary[object[2].text]['user_metadata'] = [] 
                            for user_metadata_list in object.iter(NS + "UserMetadataList"):
                                for user_meta in user_metadata_list.iter(NS + "Metadata"):
                                    
                                    object_dictionary[object[2].text]['user_metadata'].append((user_meta[0].text, user_meta[1].text, user_meta[2].text))
                                                        
            parsed_list.append(object_dictionary)

        else:
            parsed_list = []
            for object in tree.iter(NS + "DirectoryList"):
                    for object in object.iter(NS + "DirectoryEntry"):
                        parsed_list.append((object[0].text,object[1].text, object[2].text))
                        
        return parsed_list
    
    
    def __parse_object_info_response(self, response):
        tree = fromstring(response)
        NS = "{http://www.emc.com/cos/}"
        
        object_dictionary = {}
        
        for object in tree.iter(NS + "GetObjectInfoResponse"):
            
            object_tag0 = object[0].tag.split("}")
            object_tag1 = object[1].tag.split("}")
            object_tag2 = object[2].tag.split("}")
            object_tag3 = object[3].tag.split("}")
            object_tag4 = object[4].tag.split("}")
            object_tag5 = object[5].tag.split("}")
            
            
            for replica in object.iter(NS + "replicas"):
                for item in replica.iter(NS + "replica"):
                    
                    item0 = item[0].tag.split('}')
                    item1 = item[1].tag.split('}')
                    item2 = item[2].tag.split('}')
                    item3 = item[3].tag.split('}')
                    
                    if object[0].text not in object_dictionary:
                        object_dictionary[object[0].text] = {}
                        object_dictionary[object[0].text]['replicas'] = {}
                        object_dictionary[object[0].text]['replicas'] = []
                        
                    object_dictionary[object[0].text]['replicas'].append((item[0].text, item[1].text, item[2].text, item[3].text, item[4].text))
                object_dictionary[object[0].text][object_tag1[1]] = (object[1].text)
                object_dictionary[object[0].text][object_tag2[1]] = (object[2].text)
                #object_dictionary[object[0].text][object_tag3[1]] = (object[3][0].text, object[3][1].text)
                object_dictionary[object[0].text][object_tag4[1]] = (object[4][0].text)
                object_dictionary[object[0].text][object_tag5[1]] = (object[5][0].text, object[5][1].text)

        return object_dictionary
    
    def __parse_version_information(self, response):
        tree = fromstring(response)
        NS = "{http://www.emc.com/cos/}"
        for version in tree.iter(NS + "Atmos"):                
            return version.text


class RequestWithMethod(urllib2.Request):                                                                       # Subclass the urllib2.Request object and then override the HTTP methom

    def __init__(self, method, *args, **kwargs):
        self._method = method
        urllib2.Request.__init__(self, *args, **kwargs)
   
    def get_method(self):
        return self._method

class EsuException(Exception):
    def __init__(self, http_code, atmos_error):
        self.http_code = http_code
        self.atmos_error_code = atmos_error.code.text
        self.atmos_error_message = atmos_error.message.text
    def __str__(self):
        return repr(self)

#TODO:
  
    # Atmos 1.3.x features
    def list_versions():
        pass
    
    def version_object():
        pass
    
    def restore_version():
        pass
    







