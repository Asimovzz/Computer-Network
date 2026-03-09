
#define RECV_SIZE 256
#define SEND_SIZE 102400 

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>


// helpers
int to_base64(char* dst, char* src, int size);
int uuencode(char* file_name, char* dst_buff);
int prepare_DATA(char* from_email, char* to_email, char* subject, char* body, char* attach_file, char* target_DATA);


// connection 

/**********************************************************************
 * the socket descriptor is stored in cfd
**********************************************************************/
int cfd;
int establish_connection();
int close_connection();

// email sending
int request_and_response(char* request, char* response);
int send_email(char* account, char* password, char* from_email, char* to_email, 
        char* subject, char* body, char* attachment_path);




int to_base64(char* dst, char* src, int size){
    char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int str_len=strlen(src);  
    int len = 0;
    int i, j;
    
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
    dst[len]='\0'; 
  
    //以3个8位字符为一组进行编码  
    for(i=0, j=0;i<len-2;j+=3,i+=4)
    {  
        //取出第一个字符的前6位并找出对应的结果字符 
        dst[i]=base64_table[src[j]>>2];  
        //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        dst[i+1]=base64_table[(src[j]&0x3)<<4 | (src[j+1]>>4)]; 
        //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        dst[i+2]=base64_table[(src[j+1]&0xf)<<2 | (src[j+2]>>6)]; 
        //取出第三个字符的后6位并找出结果字符 
        dst[i+3]=base64_table[src[j+2]&0x3f];  
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            dst[i-2]='=';  
            dst[i-1]='=';  
            break;  
        case 2:  
            dst[i-1]='=';  
            break;  
    }
    return 0;
}


int uuencode(char* file_name, char* dst_buff){
    char cmd[50]="";
    sprintf(cmd, "uuencode %s %s > temp", file_name, file_name);
    system(cmd);
    FILE *fd = fopen("temp", "r");
    char buff[200];
    strcpy(dst_buff, "");
    // first line: three strings
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, " ");
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, " ");
    fscanf(fd, "%s", buff); strcat(dst_buff, buff); strcat(dst_buff, "\n");
    // remaining lines 
    while(fscanf(fd, "%s", buff)!=EOF){
        //printf("%s", buff);
        strcat(dst_buff, buff);
        strcat(dst_buff, "\n");
        //printf("%s", dst_buff);
    }
    system("rm temp");
}

int establish_connection(){
    // build TCP connection to PKU SMTP server
    // address (name): smtphz.qiye..163.com
    // port: 25
    // put the socker descriptor in the global variable cfd
    // find a way to translate the domain name to IP address, so you can establish the connection
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
    struct hostent *he;
    struct sockaddr_in server_addr;

    // 解析服务器域名
    if ((he = gethostbyname("smtphz.qiye.163.com")) == NULL) {
        perror("gethostbyname error");
        exit(1);
    }

    if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket error");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(25);
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if (connect(cfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect error");
        exit(1);
    }

    return 0;
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/
}

int close_connection(){
    close(cfd);
}

int request_and_response(char* request, char* response){
    // send a request and recv a response by socket
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
    printf("REQUEST: %s", request);

    if (send(cfd, request, strlen(request), 0) == -1) {
        perror("send error");
        return -1;
    }

    memset(response, 0, RECV_SIZE);
    if (recv(cfd, response, RECV_SIZE, 0) == -1) {
        perror("recv error");
        return -1;
    }
    
    printf("RESPONSE: %s\n", response);
    return 0;
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/
}


int prepare_DATA(char* from_email, char* to_email, char* subject, char* body, char* attach_file, char* target_DATA){
    char temp[102400]; // 100KB
    strcpy(target_DATA, "");
        // FROM
    sprintf(temp, "From: %s\r\n", from_email);
    strcat(target_DATA, temp);

    // build other fields: TO, SUBJECT, BODY, ATTACHMENT
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/
    char attachment_buff[102400];

    // TO
    sprintf(temp, "To: %s\r\n", to_email);
    strcat(target_DATA, temp);

    // SUBJECT
    sprintf(temp, "Subject: %s\r\n\r\n", subject);
    strcat(target_DATA, temp);

    // BODY
    sprintf(temp, "%s\r\n", body);
    strcat(target_DATA, temp);

    // ATTACHMENT
    uuencode(attach_file, attachment_buff);
    strcat(target_DATA, attachment_buff);

    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/

    strcat(target_DATA, "\r\n.\r\n");
    return 0;
}





int send_email(char* username, char* password, char* from_email, char* to_email, 
        char* subject, char* body, char* attachment_path){

    establish_connection();
    
    char temp[100];
    char rbuf[RECV_SIZE];
    char sbuf[SEND_SIZE];

    // recv from server
    recv(cfd, rbuf, RECV_SIZE, 0);
    printf("From server: %s\n", rbuf);

    // send HELO
    sprintf(sbuf, "HELO smtp\r\n");
    request_and_response(sbuf, rbuf);

    // send other requests, fill in the reqeust_and_response() function and use it here
    /*************************************************************************
    ************* start of your code *****************************************
    *************************************************************************/

	// send AUTH 
    sprintf(sbuf, "AUTH LOGIN\r\n");
    request_and_response(sbuf, rbuf);

	// send username (base64)
    char b64_username[100];
    to_base64(b64_username, username, strlen(username));
    sprintf(sbuf, "%s\r\n", b64_username);
    request_and_response(sbuf, rbuf);

	// send password (base64)
    char b64_password[100];
    to_base64(b64_password, password, strlen(password));
    sprintf(sbuf, "%s\r\n", b64_password);
    request_and_response(sbuf, rbuf);

	// send MAIL FROM
    sprintf(sbuf, "MAIL FROM: <%s>\r\n", from_email);
    request_and_response(sbuf, rbuf);

	// send RCPT TO
    sprintf(sbuf, "RCPT TO: <%s>\r\n", to_email);
    request_and_response(sbuf, rbuf);

	// send DATA
    sprintf(sbuf, "DATA\r\n");
    request_and_response(sbuf, rbuf);

	// send email (this step is complex, do it in prepare_DATA()
    char email_data[102400];
    prepare_DATA(from_email, to_email, subject, body, attachment_path, email_data);
    request_and_response(email_data, rbuf);

	// send QUIT
    sprintf(sbuf, "QUIT\r\n");
    request_and_response(sbuf, rbuf);
    /*************************************************************************
    ************* end of your code *****************************************
    *************************************************************************/



    
    // CLOSE TCP
   
    close_connection();

    return 0;
}
