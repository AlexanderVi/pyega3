import unittest
import tempfile
import random
import string
import json

import unittest.mock as mock
import requests
import responses

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
        good_credentials = (rand_str(), rand_str(), rand_str())

        url_base  =  "https://ega.ebi.ac.uk:8443/ega-openid-connect-server/token"
        url_base +=  "?grant_type=password"
        url_base +=  "&client_id=f20cd2d3-682a-4568-a53e-4262ef54c8f4"
        url_base +=  "&scope=openid"
        
        good_url  = url_base
        good_url += "&client_secret="+good_credentials[2]                     
        good_url += "&username="     +good_credentials[0]
        good_url += "&password="     +good_credentials[1]
        

        id_token     = rand_str()
        access_token = rand_str()        
        
        responses.add(
            responses.POST, 
            good_url, 
            match_querystring = True,
            json={"id_token":id_token, "access_token":access_token, "token_type":"Bearer", "expires_in": 3600}, 
            status=200 )    

        resp_token = pyega3.get_token(good_credentials)   
        self.assertEqual( resp_token, access_token )

        bad_credentials = (rand_str(), rand_str(), rand_str())
        
        bad_url  = url_base
        bad_url += "&client_secret="+bad_credentials[2] 
        bad_url += "&username="     +bad_credentials[0]
        bad_url += "&password="     +bad_credentials[1]               
                
        responses.add(
            responses.POST, 
            bad_url, 
            json={"error": "invalid_grant","error_description": "Bad credentials"},
            status=400 )    
        
        resp_token = pyega3.get_token(bad_credentials)   
        self.assertEqual( resp_token, access_token )


        

        '''
        def request_callback(request):
                #payload = json.loads(request.body)                
                #resp_body = {'value': sum(payload['numbers'])}
                headers = {}
                resp_body={"id_token": id_token, "access_token": access_token, "token_type": "Bearer", "expires_in": 3600 }
                return (200, headers, json.dumps(resp_body) )
        
        responses.add_callback(
                responses.POST, url,
                callback=request_callback,
                content_type='application/json',
            )        
        #resp = requests.get( url )
        ''' 
        #resp_json = resp.json()
        #print("------------------------------------------------->>>>>>>>>>>>>>>>>>>>>>>-----------------")
        #print( json.dumps(resp_json) )         
                
        #self.assertEqual( resp_json["id_token"]    ,  id_token     )
        #self.assertEqual( resp_json["access_token"],  access_token )
        #self.assertEqual( "token_type"             ,  "Bearer"     )
        #self.assertEqual( "expires_in"             ,  "3600"       )       
        
                    
if __name__ == '__main__':
    unittest.main()