import unittest
import tempfile
import random
import string
import json
import sys

import unittest.mock as mock
import requests
import responses
from urllib import parse

import pyega3.pyega3 as pyega3

def random_string(length):
    return ''.join(random.choice(string.ascii_letters+string.digits) for m in range(length))
def rand_str(min_len=6, max_len=127):
    return random_string(random.randint(1, max_len))

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
        
        # with mock.patch('requests.get', mock.Mock(side_effect = lambda k:{'aurl': 'a response', 'burl' : 'b response'}.get(k, 'unhandled request %s'%k)))                
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

    @unittest.skipIf(sys.platform.startswith("win"), "test does not work on Windows")
    def test_load_credentials(self):
        dict={"username":rand_str(),"password":rand_str(),"key":rand_str(),"client_secret":rand_str()}
        with tempfile.NamedTemporaryFile(mode='w') as tf:
            json.dump(dict,tf)
            tf.flush()
            result = pyega3.load_credentials(tf.name)            
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

        good_token     = rand_str()       

        def request_callback(request):   
            auth_hdr = request.headers['Authorization']
            if auth_hdr is not None and auth_hdr == 'Bearer ' + good_token:
                return ( 200, {}, json.dumps(["EGAD00000000001", "EGAD00000000002","EGAD00000000003"]) )
            else:
                return ( 400, {}, json.dumps({"error_description": "invalid token"}) )
                
        responses.add_callback(
            responses.GET, url,
            callback=request_callback,
            content_type='application/json',
            )        

        resp_json = pyega3.api_list_authorized_datasets(good_token)
        self.assertEqual( len(resp_json), 3 )
        self.assertEqual( resp_json[0], "EGAD00000000001" )
        self.assertEqual( resp_json[1], "EGAD00000000002" )
        self.assertEqual( resp_json[2], "EGAD00000000003" )

        bad_token = rand_str()
        with self.assertRaises(requests.exceptions.HTTPError):
            pyega3.api_list_authorized_datasets(bad_token)
                    
if __name__ == '__main__':
    unittest.main()
