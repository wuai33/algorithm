#include "emailDecode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
#include "base64.h"
#include "ucharcode.h"
*/

#define SRC_CHAR_SIZE 3                //源码3个字节
#define BASE_CHAR_SIZE 4               //编码后4个字节
#define CHAR_SIZE 8                    //一个字节有8bits
#define BASE_DATA_SIZE 6               //base编码中6个bits是实际数据

#define BUFF_SIZE 1024*2              //base编码中6个bits是实际数据

#define DEFAULT_CODE "UTF-8"


int base64_decode_value(char value_in){
    static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56
        ,57,58,59,60,61,-1,-1,-1,-2,-1
        ,-1,-1,0,1,2,3,4,5,6,7
        ,8,9,10,11,12,13,14,15,16,17
        ,18,19,20,21,22,23,24,25,-1,-1
        ,-1,-1,-1,-1,26,27,28,29,30,31
        ,32,33,34,35,36,37,38,39,40,41
        ,42,43,44,45,46,47,48,49,50,51};

    static const char decoding_size = sizeof(decoding);
    //+ 的ascll值是43
    value_in -= 43;
    if (value_in < 0 || value_in >= decoding_size) return -1;
    return decoding[(int)value_in];
}

/********************************************************
   Func Name: base64_decode_calculate
Date Created: 2018-8-3
 Description: 解码算法
       Input:       code_in;编码后的文件
                  length_in：编码后的文件长度
      Output: plaintext_out：源文件
                     outlen：源文件长度
      Return:
     Caution: plaintext_out内存由调用函数释放
*********************************************************/
int base64_decode_calculate(char *code_in, int length_in, char **plaintext_out, int *outlen){
    int i = 0, j = 0;
    int iPadNum = 0;

    char * pcIndex = code_in + length_in - 1;
    int iSrcLen = 0;
    char *pcOut = NULL;

    if (NULL == code_in || NULL == plaintext_out || NULL == outlen)
        return -1;

    //计算有几个"="，同时pcSrc指向最后一个"="，从后向前查找，这样会略过结尾可能出现的无效字符
    while(*pcIndex-- == '='){
      iPadNum++;
     }

      //计算源文件的字符个数，因为是4个编码资源对应3个源码字符，同时减去补齐用的字符个数
    iSrcLen = length_in/4*3 - iPadNum;

    //末尾增加\0
    if(*plaintext_out==NULL){
    	printf("NULL **plaintext_out for base64 decode,so malloc.\n");
    	*plaintext_out = (char *)malloc(sizeof(char)*iSrcLen + 1);
    	if (NULL == plaintext_out)
    	    return -2;
     }

    pcOut=*plaintext_out;

    memset(pcOut, 0, sizeof(char)*iSrcLen + 1);

    for (i = 0, j = 0; i < length_in; i += 4){  //一下子取4个字符进行解码，i用来索引base，j用来索引解码后的

    	//2.如果是最后那4个码，特殊处理，因为存在补齐
		if ((i == length_in-4) && iPadNum > 0){

			//如果是补了1个，那么实际上有两个字符 用3个base字符表示，于是根据这3个base重构出两个原符
			//例如：00-101010  00-110011 00-010100  ----> 10101011 00110101
			if (1 == iPadNum){
				//字符1
				pcOut[j] = (base64_decode_value(code_in[i]) << 2) + (base64_decode_value(code_in[i+1]) << 2 >> 6 & 0x3);  //先移除前2个0，再后移6位，取最后2位，相当于取base的前2位
				//字符2
				pcOut[j+1] = (base64_decode_value(code_in[i+1]) << 4) + (base64_decode_value(code_in[i+2]) << 2 >> 4 & 0xf);  //取第2个base剩下的4位，加上第3个base的后4位
				j += 2;
			}else if (2 == iPadNum){  //实际上有1个字符数据 用2个base字符表示
				pcOut[j] = (base64_decode_value(code_in[i])<<2) + (base64_decode_value(code_in[i+1]) << 2 >> 6 &0x3);
				j++;
			}

		//1.如果是之前的码，则取4个base，计算得到3个源码
		}else{
			//字符1
			pcOut[j] = (base64_decode_value(code_in[i])<<2) + (base64_decode_value(code_in[i+1]) << 2 >> 6 &0x3);
			//字符2
			pcOut[j+1] = (base64_decode_value(code_in[i+1]) << 4) + (base64_decode_value(code_in[i+2]) << 2 >> 4 & 0xf);
			//字符3
			pcOut[j+2] = (base64_decode_value(code_in[i+2]) << 6) + (base64_decode_value(code_in[i+3]) & 0x3f);
			j += 3;
		}
    }

    pcOut[iSrcLen] = '\0';
    *outlen = iSrcLen;

    return 0;
}

////for debug
#define RESERVED_COUNT_FOR_DECODE 10
//char reserved[RESERVED_COUNT_FOR_DECODE + 2]={0};
//char reserved[RESERVED_COUNT_FOR_DECODE + 2]={3,1};
char reserved[RESERVED_COUNT_FOR_DECODE + 2]={1,'b','a'};

int Base64DecodeForEmail(char *buf_in, int length_in, char **buf_out){
	int ret = 0;
	int i =0;
	int base64Flag=EMAIL_STEP_INIT;

	printf(">>>>>>INPUT(%d):%s\n",length_in,buf_in);

	//指向输入流的头和尾
	char *pInCur = buf_in;
	//char *pInEnd = buf_in + length_in -1;
	char *pInEnd = buf_in + length_in -2;  //过滤掉自动添加的换行符，debug

	//动态申请一块临时存储，用来存放被加密的内容,
	char *encodeBuf=(char *)malloc(length_in + BASE64_TUPLE_SIZE);
	int encodeLen=0,leftCount=0;
	char * encodeCur=encodeBuf;

	//指向协议自己申请的:用来存放处理结果，即整封明文邮件，包括本身就是明文的 和 base64解密后的
	char *pOutStart, *pOutCur=NULL;
	char *pReservedCur=NULL;   //用来指向上一个包遗留下来的内容

	pReservedCur=reserved;
	pOutStart=(char *)malloc(4096*10);



	//针对每一加密段落的处理结果：
	pOutCur=pOutStart;
	int decodeLen=0;

	//encodeCur=encodeBuf+encodeLen;
	//一：  如果上一次有遗留
	char conditionType=*pReservedCur;
	leftCount=strlen(pReservedCur+1);
	if(conditionType>EMAIL_CONDITION_IDLE){
		printf("The Condition(%d) was recorded from last receipt,the reserved first char is %d,the bunch chars is:%s, length:%d\n",
				conditionType,*(pReservedCur+1),pReservedCur+1,leftCount);

		switch(conditionType){
			case EMAIL_CONDITION_HUNTING:   //1
				if(leftCount == BASE64_PATTERN_SIZE)  //刚好是base64 flag结束
					base64Flag=EMAIL_STEP_READY;
				else if(leftCount < BASE64_PATTERN_SIZE){  //如果此次刚好是接上了上一包的base64 flag
					int needcount = BASE64_PATTERN_SIZE - leftCount;
					if(length_in > needcount && memcmp(pInCur,BASE64_PATTERN+leftCount,needcount)==0){
						base64Flag=EMAIL_STEP_READY;
						pInCur += needcount;
					}
				}
				break;
			case EMAIL_CONDITION_HUNTED_HUNG:  //2    //如果上一次是base64\r\n\r
				if CHECK_CRLF_OR(pInCur){
					base64Flag=EMAIL_STEP_CIPHER_WALK;
					pInCur++;
				}
				else
					base64Flag=EMAIL_STEP_READY;
				break;
			case EMAIL_CONDITION_HUNTED_PLAIN_HUNG:  //3   //如果上一次是base64\r\nxxxx(明文)或者base64\r\nxxxx\r\n\r
				leftCount = *(pReservedCur+1);
				if(leftCount>0){
					char *tmp=pInCur;
					while(leftCount<BASE64_CIPHER_SEPARATOR_LEN){
						if CHECK_CRLF_NOR(tmp)break;
						tmp++;
						leftCount++;
					}
					if(leftCount==BASE64_CIPHER_SEPARATOR_LEN){
						pInCur=tmp;
						base64Flag=EMAIL_STEP_CIPHER_WALK;   //和上一次遗留的内容共同构成两组CRLFs,于是表示正式进入密文阶段
						break;
					}
				}
				base64Flag=EMAIL_STEP_READY_PLAIN;
				break;
			case EMAIL_CONDITION_CIPHER_NULL:     //4
				base64Flag=EMAIL_STEP_CIPHER_WALK;
				break;
			case EMAIL_CONDITION_CIPHER_LINE_HUNG:	//5
				if CHECK_CRLF_OR(pInCur)
					base64Flag=EMAIL_STEP_CIPHER_LINEOVER;
				else
					base64Flag=EMAIL_STEP_CIPHER_WALK;
				break;
			case EMAIL_CONDITION_CIPHER_LINE_OVER:		//6
				base64Flag=EMAIL_STEP_CIPHER_LINEOVER;
				break;
			case EMAIL_CONDITION_CIPHER_SOME:			//7
				leftCount=strlen(pReservedCur+1);
				memcpy(encodeCur,pReservedCur+1,leftCount);
				encodeLen += leftCount;
				encodeCur += leftCount;
				base64Flag=EMAIL_STEP_CIPHER_WALK;
				break;
			case EMAIL_CONDITION_CIPHER_SECTION_HUNG:		//8
				if CHECK_CRLF_OR(pInCur)  //段落结束，也没有需要解码的，直接跳过手自符从初始状态开始
					pInCur++;
				else
					base64Flag=EMAIL_STEP_CIPHER_WALK;
				break;
			default:
				break;
		}

		printf("Based on the reserved from last receipt and this input,now the step of decode is:%d\n",base64Flag);
		memset(pReservedCur,0,BASE64_CHARS_SIZE+1);
	}

	//结合上一次的余留，开始正式walk输入流
	while (pInCur<=pInEnd) {

		//begin base64Flag==true
		if(base64Flag>=EMAIL_STEP_READY){

			//1.找到base64标志了，可以准备开始解析密文了，首先要找到密文的入口
			if(base64Flag==EMAIL_STEP_READY)
			{
				if(pInEnd==pInCur){
					/*情况2: base64标志后面只有一个字符(可能是换行符，也可能是明文符)*/
					if CHECK_CRLF_AND(pInCur){
						pReservedCur[0]=EMAIL_CONDITION_HUNTED_HUNG;
						*(pReservedCur+1)=*pInCur;
					}else
						pReservedCur[0]=EMAIL_CONDITION_HUNTED_PLAIN_HUNG;
					printf("[Condition %d]There only one char(%d), so reserve the for the next package.\n",pReservedCur[0], *pInCur);
					goto end;
				}
				//1.1如果接下来是一组CRLF, 则将是密文
				if CHECK_CRLF_AND(pInCur){
					//*pOutCur++ = *pInCur++;  //之后指向\n    debug
					//情况4: 一个密文还没有报文就结束了
					if(pInEnd==pInCur){
						pReservedCur[0]=EMAIL_CONDITION_CIPHER_NULL;
						printf("[Condition %d]There is no char left to decode(but cipher comes next), so record this for the next package.\n",pReservedCur[0]);
						goto end;
					}

					*pOutCur++ = *pInCur++; //之后指向第一个密文
					if(pInEnd==pInCur){     //如果只有一个密文
						*encodeCur=*pInCur;
						encodeLen++;
						goto end;
					}
					base64Flag = EMAIL_STEP_CIPHER_WALK;
					continue;
				}

				//1.2否则将是密文
				base64Flag = EMAIL_STEP_READY_PLAIN;
			}

			//2.表示接下来是密文
			if(base64Flag >= EMAIL_STEP_CIPHER_WALK)
			{
				//接下来才是真正的密文们....
				while(pInCur < pInEnd){
					//begin step 1
					if(base64Flag == EMAIL_STEP_CIPHER_WALK)
					{
						//1)找到密文的行结束符
						if CHECK_CRLF_AND(pInCur){
							//pInCur++;   //指向\r\n中的\n               debug
							//情况3: 一行密文结束了，同时报文也结束了
							if(pInCur == pInEnd){
								pReservedCur[0]=EMAIL_CONDITION_CIPHER_LINE_OVER;
								printf("[Condition %d]This encode line is over and the package is over, so record this condition.\n",pReservedCur[0]);
								goto end;
							}

							//2)找到密文的行结束符后，只剩下一个字符了
							pInCur++;   //指向下一行的第一个字符
							if(pInCur == pInEnd){
								//情况5: 一个加密段落即将结束，段落的结束 符应该是\r\n，但是这里只有一个
								if CHECK_CRLF_OR(pInCur) {
									pReservedCur[0]=EMAIL_CONDITION_CIPHER_SECTION_HUNG;
									pReservedCur[1]=*pInCur;
									printf("[Condition %d]There left one char:%d after one line over, so record this and reserve it for the next package.\n",pReservedCur[0],*pInCur);
								}else{
									*encodeCur=*pInCur;
									encodeLen++;
								}
								goto end;
							}

							base64Flag = EMAIL_STEP_CIPHER_LINEOVER;
							continue;
						}

						//0)一般的密文字符
						encodeLen++;
						*encodeCur++=*pInCur++;

						//5)一般的最后一个字符
						if(pInCur == pInEnd){
							//情况5: 发现最后一个字符是部分行结束符
							if CHECK_CRLF_OR(pInCur) {
								pReservedCur[0]=EMAIL_CONDITION_CIPHER_LINE_HUNG;
								pReservedCur[1]=*pInCur;
								printf("[Condition %d]There left one CRLF char:%d of one line, so reserve it for the next package.\n",pReservedCur[0],*pInCur);
							} else {
								*encodeCur=*pInCur;
								encodeLen++;
							}
							goto end;
						}
						continue;
					} //end step  1

					//begin step 2
					if(base64Flag == EMAIL_STEP_CIPHER_LINEOVER)
					{
						//3）找到密文的行结束符后，又一组CRLF, 则表示找到了密文的段落结束符
						if CHECK_CRLF_AND(pInCur)
							base64Flag = EMAIL_STEP_CIPHER_SECTIONOVER;
						else
							base64Flag = EMAIL_STEP_CIPHER_WALK;
					}//end step 2

					//begin step 3
					if(base64Flag == EMAIL_STEP_CIPHER_SECTIONOVER)
					{
						ret=base64_decode_calculate(encodeBuf,encodeLen,(char **)&pOutCur, &decodeLen);
						printf("(%d)Decode Base64 %d ciphertext(%s) to %d plaintest(%s).\n",ret,encodeLen,encodeBuf,decodeLen,pOutCur);
						//log_Debug("Decode Base64 %d ciphertext(%.16s) to %d plaintest(%.16s).",encodeLen,encodeBuf,decodeLen,pOutCur);

						pOutCur += decodeLen;
						memset(encodeBuf,0,encodeLen);
						encodeCur=encodeBuf;
						encodeLen=0;  //此段落的编码结束，归零
						base64Flag=EMAIL_STEP_INIT;
						break;
					}//end  step 3

				}//wark 密文结束

			}//该段落的密文处理结束

			//3.明文的内容，则直接加入到明文流中   //EMAIL_STEP_READY_PLAIN
			else if (base64Flag==EMAIL_STEP_READY_PLAIN)
			{
				*pOutCur++ = *pInCur++;

				int count=0;

				while(CHECK_CRLF_OR(pInCur+count) && (pInCur+count)<=pInEnd)count++;

				if (pInCur+count-1 == pInEnd){   //最后剩的是换行符，剩几个存几个
					if(count>=BASE64_CIPHER_SEPARATOR_LEN)
						base64Flag = EMAIL_STEP_CIPHER_WALK;
					else
						pReservedCur[0]=EMAIL_CONDITION_HUNTED_PLAIN_HUNG;
					pReservedCur[1]=count;   //记录的是有几个换行符
					printf("[Condition %d]Left %d CRLF of the plain text between base64 flag and package end , so record it for the next package.\n",pReservedCur[0],pReservedCur[1]);
					goto end;
				}

				if(count>0){
					memcpy(pOutCur,pInCur,count);
					pOutCur +=count;
					pInCur += count;
					if(count>=BASE64_CIPHER_SEPARATOR_LEN)
						base64Flag = EMAIL_STEP_CIPHER_WALK;
				}

				continue;
			}

		} //end 1.
		//2.begin base64Flag 如果有没有base64标志，说明全都是明文，需要找到base64\r\n开始的地方
		else if(base64Flag==EMAIL_STEP_INIT)
		{
			//情况1: 当还在寻找base64标志的时候，只剩下8个字符了,于是检查下是否含有base64\r\n子集,比如：xxxbase6
			if(pInEnd - pInCur + 1 <=BASE64_PATTERN_SIZE){
				for(i=0; i<BASE64_PATTERN_SIZE; i++){
					if(*pInEnd == BASE64_PATTERN[i]){
						if(strncmp(pInEnd-i,BASE64_PATTERN,i+1)==0){
							pReservedCur[0]=EMAIL_CONDITION_HUNTING;
							memcpy(pReservedCur+1,BASE64_PATTERN,i+1);
							printf("[Condition %d]There is left %d key word(%s) for hunting flag, so reserved for next package.\n",pReservedCur[0],i+1,pReservedCur+1);
						}
						break;
					}
				}
				goto end;
			}

			//2.2当剩下超过8个字符时,检查下是否有base64\r\n
			if('b'==(*pOutCur++ = *pInCur++))
				if('a'==(*pOutCur++ = *pInCur++))
					if('s'==(*pOutCur++ = *pInCur++))
						if('e'==(*pOutCur++ = *pInCur++))
							if('6'==(*pOutCur++ = *pInCur++))
								if('4'==(*pOutCur++ = *pInCur++))
									if('\r'==(*pOutCur++ = *pInCur++)){
										//if('\n'==(*pOutCur++ = *pInCur++))  //debug
											base64Flag=EMAIL_STEP_READY;  //找到标志位，如果接下来还是\r\n,那接下来就是密文，如果接下来不是，那就继续walk直到2个\r\n
											printf(">>>>>>>>>>..get a base64 flag,and next:%16.s\n",pInCur);
									}
		}//2.end base64Flag

	}//结束整个输入流的处理


end:
	//1.所有的编码内容都解密完，应该剩下8个的明文内容,则直接加入到输出流中
	if(base64Flag==EMAIL_STEP_INIT)
	{
		leftCount=pInEnd-pInCur+1;
		printf("There are %d chars(%.8s) left, so append to OUtbuf.\n",leftCount, pInCur);
		memcpy(pOutCur,pInCur,leftCount);
		pOutCur+=leftCount;
	}

	//2.所有的编码内容因为找不到结束符，但是已经到了报文的结尾
	else if(encodeLen>0)
	{
		leftCount=encodeLen%4;
		encodeLen -=leftCount;

		if(pReservedCur[0]==EMAIL_CONDITION_IDLE){
			memset(pReservedCur,0,BASE64_PATTERN_SIZE + 2);
			pReservedCur[0]=EMAIL_CONDITION_CIPHER_SOME;   //如果并没有结束，但是刚好是4的整数倍
			if(leftCount>0)
				memcpy(pReservedCur+1,encodeBuf+encodeLen,leftCount);  //流存剩下的那几个字符，其余的解码
			printf("[Condition %d]The count of encode is not multiple of 4 so reserve %d chars(%s) to next package.\n",
				pReservedCur[0],leftCount, pReservedCur+1);
		}

		ret=base64_decode_calculate(encodeBuf,encodeLen,&pOutCur, &decodeLen);
		printf("(%d)Decode Base64 %d ciphertext(%s) to %d plaintest(%s).\n",ret, encodeLen,encodeBuf,decodeLen,pOutCur);
		pOutCur += decodeLen;
	}

	*(pOutCur+1)='\0';
	*buf_out=pOutStart;
	free(encodeBuf);


	printf("<<<<<<<Reserved:type:(%d), content:frst char:%d, whole bunch:%s.\r\n",*pReservedCur, *(pReservedCur+1), pReservedCur+1);
	printf("<<<<<<<OUTPUT(%ld):%s\n",pOutCur-pOutStart,pOutStart);


	return pOutCur-pOutStart;
}



////////////////////////////////////测试//////////////////////////////////
int main() {
	size_t buf_len=BUFF_SIZE;
	const char *filename="./test_email.eml";
	//从文件中读取内容到缓存中
	char *buf_in,*tmp_in,*buf_out;
	buf_in=(char *)malloc(BUFF_SIZE*100);
	buf_out=(char *)malloc(BUFF_SIZE*100);
	tmp_in=buf_in;
	//memset(buf_in, 0, BUFF_SIZE);
	int read_len,totallen=0;

	FILE *file = fopen(filename, "r");
	if(file==0){
	    printf("ReadConfig, fopen file failed, filepath:%s",filename);
	    return 1;
	}


	while(1){
	  read_len=getline(&tmp_in, &buf_len, file);
	  //read_len=gets(&buf_in);
	  if(read_len==-1)
		  break;

	  tmp_in =tmp_in + read_len-1;
	  totallen +=read_len;
	  if(*tmp_in=='\n'){
		   totallen--;
	   }

	}
	fclose(file);


	Base64DecodeForEmail(buf_in, totallen, &buf_out);

	printf("The final result:%s",buf_out);

	return 0;

}

/*
 * g++ -std=c++11 -Wall -W  -Wwrite-strings -O2 -g   -o emailDecode emailDecode.cpp
 *
 *
 *
 * */
