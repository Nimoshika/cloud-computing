from basic_defs import cloud_storage, NAS
#donot modify basic_defs

import os
import sys

import boto3
import base64
import hashlib 
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

class AWS_S3(cloud_storage):
    def __init__(self):
        # TODO: Fill in the AWS access key ID
        self.access_key_id = "AKIAZ3WFZEEF2ARUKYJL"
        # TODO: Fill in the AWS access secret key
        self.access_secret_key = "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"
        # TODO: Fill in the bucket name
        self.bucket_name = "csce678-s21-p1-631000852"
         # Load client using access id and secret key
        self.client = boto3.client('s3', aws_access_key_id=self.access_key_id, aws_secret_access_key=self.access_secret_key)

   
        
    def read_block(self, offset):
        # Get object and read 
        # In AWS S3 blocks are stored as single objects
        response = self.client.get_object(Bucket=self.bucket_name, Key=str(offset))
        return bytearray(base64.b64decode(response['Body'].read()))
        
        
    def list_blocks(self):
    	# Get object in terms of dict
    	response = self.client.list_objects_v2(Bucket=self.bucket_name)
    	offset_arr = []
    	if 'Contents' in response:
        	for i in response['Contents']:
        		offset_arr.append(int(i['Key']))
		return offset_arr 
		
    def write_block(self, block, offset):
        # Store as base64 strings
        self.client.put_object(Body=base64.b64encode(block), Bucket=self.bucket_name, Key=str(offset))
        
    def delete_block(self, offset):
        # Using offset
        self.client.delete_object(Bucket=self.bucket_name, Key=str(offset))
    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from boto3
    #     boto3.session.Session:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
    #     boto3.resources:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html
    #     boto3.s3.Bucket:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#bucket
    #     boto3.s3.Object:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#object


class Azure_Blob_Storage(cloud_storage):
    def __init__(self):
        # TODO: Fill in the Azure key
        self.key = "u04DPr/UGGADYcl27vrXG3lAZ7cMP7LC+4Y3NKuR3nL8jLkp0xwG9NRzfCtDHG2nn4xX4adldrHfFmhRtT3afA=="
        # TODO: Fill in the Azure connection string
        self.conn_str = "DefaultEndpointsProtocol=https;AccountName=csce678s21;AccountKey=u04DPr/UGGADYcl27vrXG3lAZ7cMP7LC+4Y3NKuR3nL8jLkp0xwG9NRzfCtDHG2nn4xX4adldrHfFmhRtT3afA==;EndpointSuffix=core.windows.net"
        # TODO: Fill in the account name
        self.account_name = "csce678s21"
        # TODO: Fill in the container name
        self.container_name = "csce678-s21-p1-631000852"
        # Load client using connection string
        self.client = BlobServiceClient.from_connection_string(conn_str=self.conn_str)
        # Load client's container that contains blob
        self.container = self.client.get_container_client(container=self.container_name)
        
    def read_block(self, offset):
        # Get the blob from the specified container and read from the blob
        response = self.client.get_blob_client(container=self.container_name, blob=str(offset))
        # To read we can use content_as_bytes, or content_as_text, readall
        return bytearray(base64.b64decode(response.download_blob().content_as_bytes()))
        
    def write_block(self, block, offset):
        # Store as base64 strings
        self.client.get_blob_client(container=self.container_name, blob=str(offset)).upload_blob(data=base64.b64encode(block), overwrite=True)
    
    def list_blocks(self):
    	# Get blob in terms of iterator, if it is empty return empty array
    	response = self.container.list_blobs()
    	offset_arr = []
    	for i in response:
            offset_arr.append(int(i.name))
        return offset_arr    
    
    def delete_block(self, offset):
        # Delete the blob using the given offset
        self.client.get_blob_client(container=self.container_name, blob=str(offset)).delete_blob()
        
    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from azure.storage.blob
    #    blob.BlobServiceClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
    #    blob.ContainerClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python
    #    blob.BlobClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient?view=azure-python

class Google_Cloud_Storage(cloud_storage):
    def __init__(self):
        # Google Cloud Storage is authenticated with a **Service Account**
        # TODO: Download and place the Credential JSON file
        self.credential_file = "gcp-credential.json"
        # TODO: Fill in the container name
        self.bucket_name = "csce678-s21-p1-631000852"
        # Load client using the JSON file
        self.client = storage.Client.from_service_account_json(self.credential_file)
        # Load client's bucket that contains blob
        self.bucket = self.client.bucket(self.bucket_name)
        
    def read_block(self, offset):
        # Get the blob from the specified bucket and read from the blob
        # Download the blob as string and return bytearray
        response = self.bucket.blob(str(offset)).download_as_string()
        return bytearray(base64.b64decode(response))
        
    def write_block(self, block, offset):
        # Store as base64 strings
        self.bucket.blob(str(offset)).upload_from_string(base64.b64encode(block))
    
    def list_blocks(self):
    	# Get blob in terms of iterator, if it is empty return empty array
    	response = self.bucket.list_blobs()
    	offset_arr = []
    	for i in response:
            offset_arr.append(int(i.name))
        return offset_arr    
    
    def delete_block(self, offset):
        # Delete the blob using the given offset
        self.bucket.blob(str(offset)).delete()

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from google.cloud.storage
    #    storage.client.Client:
    #        https://googleapis.dev/python/storage/latest/client.html
    #    storage.bucket.Bucket:
    #        https://googleapis.dev/python/storage/latest/buckets.html
    #    storage.blob.Blob:
    #        https://googleapis.dev/python/storage/latest/blobs.html

class RAID_on_Cloud(NAS):
    def __init__(self):
        self.backends = [
                AWS_S3(),
                Azure_Blob_Storage(),
                Google_Cloud_Storage()
            ]
        self.fds = dict()    
   
    
    def open(self, filename):
        newfd = None
        for fd in range(256):
            if fd not in self.fds:
                newfd = fd
                break
        if newfd is None:
            raise IOError("Opened files exceed system limitation.")
        self.fds[newfd] = filename
        return newfd
        
        
    def get_cloud_from_hash_map(self,key):
        hash_value = hash(key)
        mod_val = hash_value%3
        cloud_picked = [x for i,x in enumerate(self.backends) if i!=mod_val]
        block = hashlib.sha256(key).hexdigest()
        block_offset = int(block,16)
        return cloud_picked, block_offset
    
    def read(self, fd, length, offset):
        
        
        output = bytearray()
        
        
        if fd not in self.fds:
            return output
        else:
            filename = self.fds[fd]
            #step 2: do the alignment
            align_offset =  int(offset/4096) 
            end_block = int(((offset+length)/4096))
            number_blocks = end_block - align_offset + 1 
      
            for i in range(number_blocks): 
                cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(align_offset+i))
                
                if block_offset not in cloud_picked[0].list_blocks():
                    break
                else:
                    block = cloud_picked[0].read_block(block_offset)
                
                if i==0: #first block
                    if (offset%4096) + length < 4096:
                        output = block[(offset%4096):(offset%4096)+length] #e.g skip first 4 bytes from the first block if the offset is 5000 (e.g hello.txt, 5000)
                    else:
                        output = block[(offset%4096):4096] #
                
                elif i==number_blocks-1: 
                    if ((offset+length)%4096) == 0:
                         output +=  block
                    else:
                        output += block[0:(offset+length)%4096] #going only until last block trim
                else:
                    output +=  block #all
                
        return output
    
    def write(self, fd, data, offset):
       
        filename = self.fds[fd]
        d = bytearray(data)
        length = len(d)
        start_block = int(offset/4096)
        ending_block = int((offset+length)/4096)
        no_of_blocks = ending_block - start_block + 1
        
        x = 0
        for i in range(no_of_blocks):
          cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(start_block+i))
          if i == 0:
                x = 4096-(offset%4096)
          
          for c in cloud_picked:
                existing_blocks = c.list_blocks()
                if block_offset in existing_blocks:
                    block = c.read_block(block_offset)
                else:
                    block = bytearray()
                if i == 0:
                    #print("First block", len(data[0:x]))
                    block[offset%4096:] = data[0:x]
                elif i == no_of_blocks-1:
                    #print("Last Block", len(data[x:x+4096]))
                    if ((offset+length)%4096) == 0:
                        block = data[x:]
                    else:
                        block[0:((offset+length)%4096)] = data[x:]
                else:
                    #print("Middle Block", len(data[x:x+4096]))
                    block[0:4096] = data[x:x+4096]
                c.write_block(block,block_offset)
                
          if i > 0:
                x = x+4096 
    
    def delete(self, filename):
        
        blocks_exist = True
        i = 0
        
        while blocks_exist:
            
            cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(i))
            for c in cloud_picked:
                if block_offset in c.list_blocks():
                    c.delete_block(block_offset)
                else:
                    blocks_exist = False
                    break
            i = i + 1
    
    def close(self, fd):
        
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)
        del self.fds[fd]
        return

