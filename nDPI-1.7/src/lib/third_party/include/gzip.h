#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#ifndef _ZSTREAM_H
#define _ZSTREAM_H
#define  Z_HEADER_SIZE 12
#define MY_BUFF_SIZE 1024
#define segment_size 1460
int ungzip(char* source,int len,char*des)
{
	int ret,have;
	int offset=0;
	void * buff = source;
	z_stream d_stream;
	char uncompr[MY_BUFF_SIZE]={0};

	d_stream.zalloc = Z_NULL;
	d_stream.zfree = Z_NULL;
	d_stream.opaque = Z_NULL;
	d_stream.next_in = Z_NULL;//inflateInit和inflateInit2都必须初始化next_in和avail_in
	d_stream.avail_in = 0;//deflateInit和deflateInit2则不用
	
	ret = inflateInit2(&d_stream,47);
	d_stream.next_in= buff;
	d_stream.avail_in= len;

	do
	{
	 bzero(uncompr, MY_BUFF_SIZE);
	 d_stream.next_out=(Bytef *)uncompr;
	 d_stream.avail_out=MY_BUFF_SIZE;

	 ret = inflate(&d_stream,Z_NO_FLUSH);
	 assert(ret != Z_STREAM_ERROR);
	 if (ret != Z_OK && ret != Z_STREAM_END)
     {
       //printf("\ninflate ret = %d\n", ret);
	//printf("%s\n ", des);
       break;
     }
	 have=MY_BUFF_SIZE-d_stream.avail_out;
	 memcpy(des+offset,uncompr,have);
	 offset+=have;
	}while(d_stream.avail_out==0);
	inflateEnd(&d_stream);
	memcpy(des+offset,"\0",1);
	return ret;
}




int ungzip1(char* source,int len,char*des)
{
	int ret,have;
	int offset=0;
	z_stream d_stream;
	Byte compr[segment_size]={0};
	Byte uncompr[segment_size*4]={0};
	memcpy(compr,(Byte*)source,len);
	uLong comprLen, uncomprLen;
	comprLen =len;//一开始写成了comprlen=sizeof(compr)以及comprlen=strlen(compr)，后来发现都不对。
	//sizeof(compr)永远都是segment_size，显然不对，strlen(compr)也是不对的，因为strlen只算到\0之前
	uncomprLen = segment_size*4;
	strcpy((char*)uncompr, "garbage");
	d_stream.zalloc = Z_NULL;
	d_stream.zfree = Z_NULL;
	d_stream.opaque = Z_NULL;
	d_stream.next_in = Z_NULL;//inflateInit和inflateInit2都必须初始化next_in和avail_in
	d_stream.avail_in = 0;//deflateInit和deflateInit2则不用
	ret = inflateInit2(&d_stream,47);

	d_stream.next_in=compr;
	d_stream.avail_in=comprLen;
	do
	{
	 d_stream.next_out=uncompr;
	 d_stream.avail_out=uncomprLen;
	 ret = inflate(&d_stream,Z_NO_FLUSH);
	 assert(ret != Z_STREAM_ERROR);
	 if (ret != Z_OK && ret != Z_STREAM_END)
     {
       printf("\ninflate ret = %d\n", ret);
       break;
     }
	 have=uncomprLen-d_stream.avail_out;
	 memcpy(des+offset,uncompr,have);//这里一开始我写成了memcpy(des+offset,d_stream.next_out,have);
	 //后来发现这是不对的，因为next_out指向的下次的输出，现在指向的是无有意义数据的内存。见下图
	offset+=have;
	}while(d_stream.avail_out==0);
	inflateEnd(&d_stream);
	memcpy(des+offset,"\0",1);
	return ret;
}




int ungzip2(char* source,int len,char*des)
{
			void * buff = source;
			int have , offset=0;
            z_stream strm;
            bzero(&strm, sizeof(strm));
            
            if (Z_OK == inflateInit2(&strm, 31))    // 31:decompress gzip
            {
                strm.next_in    = buff;
                strm.avail_in   = len;
                
                char zbuff[MY_BUFF_SIZE] = {0};
                
                do 
                {
                    bzero(zbuff, MY_BUFF_SIZE);
                    strm.next_out = (Bytef *)zbuff;
                    strm.avail_out = MY_BUFF_SIZE;
                    
                    int zlibret = inflate(&strm, Z_NO_FLUSH);
                    
                    if (zlibret != Z_OK && zlibret != Z_STREAM_END)
                    {
                        printf("\ninflate ret = %d\n", zlibret);
			printf("%s\n ", des);
                        break;
                    }
                    
                    //printf("%s", zbuff);
                    have = MY_BUFF_SIZE - strm.avail_out;
					memcpy(des+offset,zbuff,have);
					offset += have;
                } while (strm.avail_out == 0);
            }
			inflateEnd(&strm);
            memcpy(des+offset,"\0",1);
}





int ungzip3(char* source,int len,char*des)
{
			void * buff = source;
			int have , offset=0;
            z_stream strm;
            bzero(&strm, sizeof(strm));
            
            if (Z_OK == inflateInit2(&strm, 31))    // 31:decompress gzip
            {
                strm.next_in    = buff;
                strm.avail_in   = len;
                
                char zbuff[MY_BUFF_SIZE] = {0};
                
                do 
                {
                    bzero(zbuff, MY_BUFF_SIZE);
                    strm.next_out = (Bytef *)zbuff;
                    strm.avail_out = MY_BUFF_SIZE;
                    
                    int zlibret = inflate(&strm, Z_NO_FLUSH);
                    
                    if (zlibret != Z_OK && zlibret != Z_STREAM_END)
                    {
                        printf("\ninflate ret = %d\n", zlibret);
                        break;
                    }
                    printf("%s", zbuff);
                } while (strm.avail_out == 0);
            }
			inflateEnd(&strm);
            //memcpy(des+offset,"\0",1);
}

#endif
