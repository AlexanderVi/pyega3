
import sys
import json
import time
import random
import string
import requests
import responses
import re
import unittest 
from unittest import mock

from urllib import parse
# from psutil import virtual_memory

import struct
import itertools

import pyega3.pyega3 as pyega3

def random_string(length):
    return ''.join(random.choice(string.ascii_letters+string.digits) for m in range(length))
def rand_str(min_len=6, max_len=127):
    return random_string(random.randint(1, max_len))

def rand_bytes(length, seed=None):
    if seed: random.seed(seed)
    return random.getrandbits(length*8).to_bytes(length, 'little')

# def randbytes(n,_struct8k=struct.Struct("!1000Q").pack_into):
#     if n<8000:
#         longs=(n+7)//8
#         return struct.pack("!%iQ"%longs,*map(
#             random.getrandbits,itertools.repeat(64,longs)))[:n]
#     data=bytearray(n);
#     for offset in range(0,n-7999,8000):
#         _struct8k(data,offset,
#             *map(random.getrandbits,itertools.repeat(64,1000)))
#     offset+=8000
#     data[offset:]=randbytes(n-offset)
#     return data

class MockedErrorResponse(object):
    """
    Mocked response object for requests.
    """
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.text = body

    def raise_for_status(self):
        raise requests.HTTPError()


class Pyega3Test(unittest.TestCase):

    @unittest.skip("not ready yet")
    def test_404(self):
        '''
        responses.add(
            responses.POST,
            good_url,
            match_querystring = True,
            json={"id_token":id_token, "access_token":access_token,
                "token_type":"Bearer", "expires_in": 3600},
            status=200 )
        '''

        # with mock.patch('requests.get', mock.Mock(side_effect = lambda k:{'aurl': 'a response', 
        # 'burl' : 'b response'}.get(k, 'unhandled request %s'%k)))
        body = "XXXX"
        returned_response = MockedErrorResponse(404, body)
        with mock.patch("requests.get", return_value=returned_response):
            with tempfile.TemporaryFile("wb+") as f:
                try:
                    pyega3.get("http://some_url", f)
                except Exception as e:
                    self.assertIn(body, str(e))
                else:
                    self.assertFalse(True)

    def test_load_credentials(self):
        dict={"username":rand_str(),"password":rand_str(),"key":rand_str(),"client_secret":rand_str()}
        with mock.patch('os.path.exists') as m:
            m.return_value = True
            m_open = mock.mock_open(read_data=json.dumps(dict))
            with mock.patch( "builtins.open", m_open ):                
                credentials_file = "credentials.json"
                result = pyega3.load_credentials(credentials_file)
                m_open.assert_called_once_with(credentials_file)
                self.assertEqual(len(result) , 4                     )
                self.assertEqual(result[0]   , dict["username"]      )
                self.assertEqual(result[1]   , dict["password"]      )
                self.assertEqual(result[2]   , dict["client_secret"] )
                self.assertEqual(result[3]   , dict["key"]           )    

    @responses.activate    
    def test_get_token(self):        
        url  =  "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"

        id_token     = rand_str()
        access_token = rand_str()          

        good_credentials = (rand_str(), rand_str(), rand_str())

        def request_callback(request):
            
            query = parse.parse_qs( request.body )
            if query['username'][0] == good_credentials[0] and query['password'][0] == good_credentials[1]:
                return ( 200, {}, json.dumps({"access_token": access_token, "id_token": id_token, "token_type": "Bearer", "expires_in": 3600 }) )
            else:
                return ( 400, {}, json.dumps({"error_description": "Bad credentials","error": "invalid_grant"}) )
                
        responses.add_callback(
            responses.POST, url,
            callback=request_callback,
            content_type='application/json',
            )        

        resp_token = pyega3.get_token(good_credentials)
        self.assertEqual( resp_token, access_token )

        bad_credentials = (rand_str(), rand_str(), rand_str())
        with self.assertRaises(SystemExit):
            pyega3.get_token(bad_credentials)                                

    @responses.activate    
    def test_api_list_authorized_datasets(self):        
        url = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets"

        good_token = rand_str()       
        datasets = ["EGAD00000000001", "EGAD00000000002","EGAD00000000003"]

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(datasets) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, url,
            callback=request_callback,
            content_type='application/json',
            )                

        resp_json = pyega3.api_list_authorized_datasets(good_token)
        self.assertEqual( len(resp_json), 3 )
        self.assertEqual( resp_json[0], datasets[0] )
        self.assertEqual( resp_json[1], datasets[1] )
        self.assertEqual( resp_json[2], datasets[2] )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.api_list_authorized_datasets(bad_token)

    
    @responses.activate    
    def test_api_list_files_in_dataset(self): 

        dataset = "EGAD00000000001"

        responses.add(
                responses.GET, 
                "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets",
                json=json.dumps([dataset]), status=200)

        url_files = "https://ega.ebi.ac.uk:8051/elixir/data/metadata/datasets/{}/files".format(dataset)        

        files = [
        {
            "checksum": "3b89b96387db5199fef6ba613f70e27c",
            "datasetId": dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000001",
            "checksumType": "MD5",
            "fileSize": 4804928,
            "fileName": "EGAZ00000000001/ENCFF000001.bam"
        },
        {
            "checksum": "b8ae14d5d1f717ab17d45e8fc36946a0",
            "datasetId": dataset,
            "fileStatus": "available",
            "fileId": "EGAF00000000002",
            "checksumType": "MD5",
            "fileSize": 5991400,
            "fileName": "EGAZ00000000002/ENCFF000002.bam"
        } ]

        good_token = rand_str()

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(files) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, url_files,
            callback=request_callback,
            content_type='application/json',
            )        

        resp_json = pyega3.api_list_files_in_dataset(good_token, dataset)
        
        self.assertEqual( len(resp_json), 2 )
        self.assertEqual( resp_json[0], files[0] )
        self.assertEqual( resp_json[1], files[1] )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.api_list_files_in_dataset(bad_token, dataset)

        bad_dataset  = rand_str()
        with self.assertRaises(SystemExit):
            pyega3.api_list_files_in_dataset(good_token, bad_dataset)

    @responses.activate    
    def test_get_file_name_size_md5(self):      

        good_file_id = "EGAF00000000001"
        file_size    = 4804928
        file_name    = "EGAZ00000000001/ENCFF000001.bam"
        check_sum    = "3b89b96387db5199fef6ba613f70e27c"

        good_token = rand_str()       

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps({"fileName": file_name, "fileSize": file_size, "checksum": check_sum}) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, 
            "https://ega.ebi.ac.uk:8051/elixir/data/metadata/files/{}".format(good_file_id),
            callback=request_callback,
            content_type='application/json',
            )                

        rv = pyega3.get_file_name_size_md5(good_token, good_file_id)
        self.assertEqual( len(rv), 3 )
        self.assertEqual( rv[0], file_name )
        self.assertEqual( rv[1], file_size )
        self.assertEqual( rv[2], check_sum )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.get_file_name_size_md5(bad_token, good_file_id)

        bad_file_id = "EGAF00000000000"
        with self.assertRaises(requests.exceptions.ConnectionError):
            pyega3.get_file_name_size_md5(good_token, bad_file_id)
  
    # @unittest.skip
    @responses.activate    
    def test_download_file_slice(self):

        seed = time.time()
        url = "https://test_url"
        good_token = rand_str() 
        # mem = virtual_memory().available
        mem = int(128*1024*1024)

        # file_length = random.randint(1, mem)
        file_length = mem
        start_pos   = random.randint(0,file_length)
        file_name    = "EGAZ00000000001/ENCFF000001.bam"

        def parse_ranges(s):
            return tuple(map(int,re.match(r'^bytes=(\d+)-(\d+)$', s).groups()))

        def request_callback(request):
            auth_hdr = request.headers['Authorization']
            if auth_hdr is None or auth_hdr != 'Bearer ' + good_token:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )

            start, end = parse_ranges( request.headers['Range'] )
            self.assertLess(start,end)                              
            # return ( 200, {}, bytes(n%256 for n in range(start,end+1)) )            
            # import os
            # return ( 200, {}, os.urandom(end-start+1) )
            return ( 200, {}, rand_bytes(end-start+1, seed) )
                
                
        responses.add_callback(
            responses.GET, 
            url,
            callback=request_callback
            )                
        
        self.written_bytes = 0
        expected_bytes = rand_bytes(file_length,seed)
        def mock_write(buf):
            buf_len = len(buf) 
            expected = expected_bytes[self.written_bytes:self.written_bytes+buf_len]
            self.assertEqual( expected, buf )
               
            # for i in range(0, buf_len):
            #     expected_byte = expected_bytes[self.written_bytes+i]
            #     self.assertEqual( expected_byte, buf[i] )
            self.written_bytes += buf_len
        
        m_open = mock.mock_open()
        with mock.patch( "builtins.open", m_open, create=True ):  
            m_open().write.side_effect = mock_write
            pyega3.download_file_slice(url, good_token, file_name, start_pos, file_length)
        
        self.assertEqual( file_length, self.written_bytes )

        fname_on_disk = file_name + '-from-'+str(start_pos)+'-len-'+str(file_length)+'.slice'
        m_open.assert_called_with(fname_on_disk, 'ba')
        # print(str(m_open.mock_calls))

                    
if __name__ == '__main__':
    unittest.main(exit=False)
