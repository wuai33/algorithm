
#define CHECK_CRLF_OR(tmp) (*(tmp)=='\r' || *(tmp)=='\n')
//#define CHECK_CRLF_AND(tmp) (*(tmp)=='\r' && *(tmp+1)=='\n')

#define CHECK_CRLF_AND(tmp) (*(tmp)=='\r' || *(tmp+1)=='\n')  //debug
#define CHECK_CRLF_NOR(tmp) (*(tmp)!='\r' && *(tmp)!='\n')

#define BASE64_TUPLE_SIZE 4               //编码后4个字节

////实际的email格式
//#define BASE64_CIPHER_SEPARATOR_LEN   4    //被加密的base64密文和其他明文之间的分割符长度
//#define BASE64_PATTERN_SIZE 7
//const char BASE64_PATTERN[]={'b','a','s','e','6','4','\r','\n'};  //有换行符才算接下来会是base64编码的密文


/////读取加工过的邮件文件，测试用的
#define BASE64_CIPHER_SEPARATOR_LEN   2    //debug
#define BASE64_PATTERN_SIZE 7      //debug
const char BASE64_PATTERN[]={'b','a','s','e','6','4','\r'};  //有换行符才算接下来会是base64编码的密文   debug
typedef enum
{
	EMAIL_CONDITION_IDLE = 0,        //还在捕获base64\r\n标志阶段，所以本报文的结尾处有几个 base64\r\n 中的字符就存几个，与一下一个包合并
	EMAIL_CONDITION_HUNTING = 1,        //还在捕获base64\r\n标志阶段，所以本报文的结尾处有几个 base64\r\n 中的字符就存几个，与一下一个包合并
	EMAIL_CONDITION_HUNTED_HUNG = 2,     //已经找到了base64\r\n标志，但接下来是悬而未决的状态，包括后面是一个\r,或者后面是若干明文的场景
	EMAIL_CONDITION_HUNTED_PLAIN_HUNG = 3, //base64\r\n标志后是一些明文，直到遇到双\r\n才会进入密文，所以用来标志该明文后面有几个\r\n\r
	EMAIL_CONDITION_CIPHER_NULL = 4,    //已经找到密文的入口了，但是一个密文也没有,只需要记录当前状况，不需要保存任何数据
	EMAIL_CONDITION_CIPHER_LINE_HUNG = 5,    //在解析密文的时候，刚好最后一个字符是 \r
	EMAIL_CONDITION_CIPHER_LINE_OVER = 6,    //在解析密文的时候，刚好最后是\r\n，即一行结束
	EMAIL_CONDITION_CIPHER_SOME = 7,    //保留了<4个几个密文，等待与下一个报文合并解析
	EMAIL_CONDITION_CIPHER_SECTION_HUNG = 8,    //在解析密文的时候，如果是一个段落将要结束的时候，即密文后面是\r\n\r
	EMAIL_CONDITION_BUTT
}FILTER_EMAIL_CONDITION_TYPE;

typedef enum
{
	EMAIL_STEP_INIT = 0,     	     //初始状态,或者一段密文结束解码
	EMAIL_STEP_READY = 1,          //找到了base64标志
	EMAIL_STEP_READY_PLAIN = 2,    	    //base64标志之后还存在一些明文
	EMAIL_STEP_CIPHER_WALK = 3,    //正在walk中
	EMAIL_STEP_CIPHER_LINEOVER = 4,      //walk一行密文结束
	EMAIL_STEP_CIPHER_SECTIONOVER = 5,   //结束一段密文的walk

}FILTER_EMAIL_DECODE_TYPE;

#define BASE64_CHARS_SIZE 8



void testPointandand();
void testPointandStruct();
void testBase64();
void testEmailDecode();
