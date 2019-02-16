#include "ping.h"


/* 初始化IPv4结构 */
struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, NULL, 0, IPPROTO_ICMP};

#ifdef IPV6
/* 若存在IPv6，则初始化IPv6结构 */
struct proto proto_v6 = {proc_v6, send_v6, init_v6, NULL, NULL, 0, IPPROTO_ICMPV6};
#endif

int datalen = 56;       /* data that goes with ICMP echo request */


int main(int argc, char *argv[])
{
    int ch;
    struct addrinfo *ai;
    char *h;

    opterr = 0;     /* don't want getopt() writing to stderr */

    /* 只实现ping的一个参数选项-v供查询 */
    /* 有关getopt函数的使用可以查阅相关资料 */
    while( (ch = getopt(argc, argv, "v")) != EOF)
    {
        switch(ch)
        {
            case 'v':
                verbose++;
                break;
            case '?':
                printf("unrecognize option: %c\n", ch);
                exit(1);
        }
    }

    if(optind != argc-1)
    {
        perror("usage: ping [ -v ] <hostname>");
        exit(1);
    }

    host = argv[optind];

    pid = getpid() & 0xffff;    /* ICMP ID field is 16 bits */

    MySignal(SIGALRM, sig_alrm);
    MySignal(SIGINT, statistics);

    /* 将主机名和服务名映射到一个地址，并返回指向addrinfo的指针 */
    ai = host_serv(host, NULL, 0, 0);
    /* 将网络字节序的地址转换为字符串格式地址，并返回该字符串的指针 */
    h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);

    /* 显示PING的主机名、地址与数据字节数 */
    printf("PING %s (%s) %d bytes of data.\n", ai->ai_canonname ? ai->ai_canonname : h, h, datalen);

    /* initialize according to protocol */
    if(ai->ai_family == AF_INET)
    {
        pr = &proto_v4;/* proto结构指针pr指向对应域的结构，这里是IPv4域的结构 */
#ifdef IPV6
    }else if(ai->family == AF_INET6)
    {
        pr = &proc_v6;
        if(IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr)))
        {
            perror("connot ping IPv4-mapped IPv6 address");
            exit(1);
        }
#endif
    }else
    {
        printf("unknown address family %d", ai->ai_family);
        exit(1);
    }

    pr->sasend = ai->ai_addr;/* 发送地址赋值 */
    pr->sarecv = (struct sockaddr *)Calloc(1, ai->ai_addrlen);
    pr->salen = ai->ai_addrlen;/* 地址的大小 */

    /* 处理数据 */
    readloop();

    exit(0);

}

static Sigfunc *M_signal(int signo, Sigfunc *func);
Sigfunc *MySignal(int signo, Sigfunc *func)
{
    Sigfunc *sigfunc;
    if( (sigfunc = M_signal(signo, func)) == SIG_ERR)
    {
        perror("signal error");
        exit(1);
    }
    return (sigfunc);
}
static Sigfunc *M_signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;
    /* 设置信号处理函数 */
    act.sa_handler = func;
    /* 初始化信号集 */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if(signo == SIGALRM)
    {/* 若是SIGALRM信号，则系统不会自动重启 */
#ifdef SA_INTERRUPT
        act.sa_flags |= SA_INTERRUPT;
#endif
    }
    else
    {/* 其余信号设置为系统会自动重启 */
#ifdef SA_RESTART
        act.sa_flags |= SA_RESTART;
#endif
    }
    /* 调用 sigaction 函数 */
    if(sigaction(signo, &act, &oact) < 0)
        return(SIG_ERR);
    return(oact.sa_handler);
}

/* 将主机名和服务名映射到一个地址 */
struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype)
{
    int n;
    struct addrinfo hints, *res;
    bzero(&hints, sizeof(struct addrinfo));

   hints.ai_flags = AI_CANONNAME;   /* always return canonical name，告知getaddrinfo函数返回主机的规范名字 */
   hints.ai_family = family;
   hints.ai_socktype = socktype;

   if( (n = getaddrinfo(host, serv, &hints, &res)) != 0)  /*头文件#include<netdb.h> int getaddrinfo(const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result); 返回: 若成功则为0，由result参数指向的变量已被填入一个指针，它指向的是由其中的ai_next成员串接起来的addrinfo结构链表； 若出错则为非0*/
   /*getaddrinfo解决了把主机名和服务名转换成套接字地址结构的问题。*/
   /*getaddrinfo解决了把主机名和服务名转换成套接字地址结构的问题。*/
       return(NULL);
   return(res); /* return pointer to first on linked list, 除res变量外的所有内容都是由getaddrinfo函数动态分配的内存空间(譬如来自malloc调用！！！有问题) */
}

char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	static char str[128];	/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET:{
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str))
			    == NULL)
				return (NULL);
			return (str);
		}

#ifdef	IPV6
	case AF_INET6:{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			if (inet_ntop
			    (AF_INET6, &sin6->sin6_addr, str,
			     sizeof(str)) == NULL)
				return (NULL);
			return (str);
		}
#endif

#ifdef	AF_UNIX
	case AF_UNIX:{
			struct sockaddr_un *unp = (struct sockaddr_un *)sa;

			/* OK to have no pathname bound to the socket: happens on
			   every connect() unless client calls bind() first. */
			if (unp->sun_path[0] == 0)
				strcpy(str, "(no pathname bound)");
			else
				snprintf(str, sizeof(str), "%s", unp->sun_path);
			return (str);
		}
#endif

#ifdef	HAVE_SOCKADDR_DL_STRUCT
	case AF_LINK:{
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

			if (sdl->sdl_nlen > 0)
				snprintf(str, sizeof(str), "%*s",
					 sdl->sdl_nlen, &sdl->sdl_data[0]);
			else
				snprintf(str, sizeof(str), "AF_LINK, index=%d",
					 sdl->sdl_index);
			return (str);
		}
#endif
	default:
		snprintf(str, sizeof(str),
			 "sock_ntop_host: unknown AF_xxx: %d, len %d",
			 sa->sa_family, salen);
		return (str);
	}
	return (NULL);
}

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
	char *ptr;

	if ((ptr = sock_ntop_host(sa, salen)) == NULL)
    {
        perror("sock_ntop_host error");	/* inet_ntop() sets errno */
        exit(1);
    }
	return (ptr);
}

void *Calloc(size_t n, size_t size)
{
    void *ptr = calloc(n, size);
    if ( ptr == NULL)
    {
        perror("calloc error");
        exit(1);
    }
    return ptr;
}

/* 发送数据包，并设置闹钟，一秒钟后给所在进程发送SIGALRM信号  */
void
sig_alrm(int signo)
{
	(*pr->fsend)();

	alarm(1);
	return;
}

/* 检验和算法 */
uint16_t
in_cksum(uint16_t *addr, int len)
{
	int				nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
    /* 把ICMP报头二进制数据以2字节为单位进行累加 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

		/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {/* 若ICMP报头为奇数个字节，把最后一个字节视为2字节数据的高字节，则低字节为0，继续累加 */
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

/* 在IPv4域中发送数据包 */
void
send_v4(void)
{
	int			len;
	struct icmp	*icmp;


    /* 设置ICMP报头 */
	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;/* 回显请求 */
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, datalen);	/* fill with pattern */
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);/* 记录发送时间 */

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
    /* 检验和算法 */
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    /* 发送数据包 */
	if( len != sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen))
    {
        perror("sendto error");
        exit(1);
    }
}

/*tv_sub函数，它把两个timeval结构中存放的时间值相减，并把结果存入第一个timeval中*/
void tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void readloop()
{
    int size;
    char recvbuf[BUFSIZE];
    char controlbuf[BUFSIZE];

    struct msghdr msg;
    struct iovec iov;

    ssize_t n;
    struct timeval tval;

    /* 创建ICMP的原始套接字，必须是root权限 */
    if( (sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpprot)) < 0)
    {
        perror("socket error");
        exit(1);
    }
    /* 回收root权限，设置当前用户权限 */
    setuid(getuid());
    /* 初始化IPv6 */
    if(pr->finit)
        (*pr->finit)();

    size = 60 * 1024;
    /* 设置接收缓冲区的大小为60k，主要为了减小接收缓冲区溢出 */
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    /* 发送第一个数据包 */
    sig_alrm(SIGALRM);

    /* 初始化接收缓冲区 */
    iov.iov_base = recvbuf;
    iov.iov_len = sizeof(recvbuf);
    msg.msg_name = pr->sarecv;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlbuf;

    for( ; ;)
    {
        /* 接收ICMP数据包 */
        msg.msg_namelen = pr->salen;
        msg.msg_controllen = sizeof(controlbuf);
        /* 从套接字接收数据 */
        n = recvmsg(sockfd, &msg, 0);
        if(n < 0)
        {
            if(errno == EINTR)
                continue;
            else
            {
                perror("recvmsg error");
                exit(1);
            }
        }
        /* 记录接收时间 */
        gettimeofday(&tval, NULL);
        /* 调用处理函数 */
        (*pr->fproc)(recvbuf, n, &msg, &tval);
    }
}

/*proc_v4函数,它处理所有接收到的ICMPv4消息。其中涉及的IPv4首部格式见文献
	另外需知，当一个ICMPV4消息由进程在原始套接字上收取时，内核已经证实它的IPv4首部和ICMPv4首部中的基本字段的有效性
*/
void
proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct ip *) ptr;		/* start of IP header */
    /* IP报文首部长度，即IP报文首部的长度标志乘以4 */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	if (ip->ip_p != IPPROTO_ICMP)
		return;				/* not ICMP */

    /* 越过IP报头，指向ICMP报头 */
	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
    /* ICMP报头及ICMP数据报的总长度，若小于8，则不合理 */
	if ( (icmplen = len - hlen1) < 8)
		return;				/* malformed packet */

    /* 确保所有接收的数据报是ICMP回显应答 */
	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			return;			/* not enough data to use */

		tvsend = (struct timeval *) icmp->icmp_data;
        /* 计算接收和发送的时间差 */
		tv_sub(tvrecv, tvsend);
        /* 以毫秒为单位计算rtt */
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

        /* 打印相关信息 */
		printf("%d bytes from %s: icmp_seq=%u  ttl=%d  rtt=%.3f ms\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ip_ttl, rtt);
        nrecv++;

	} else if (verbose) {
		printf("  %d bytes from %s: icmp_type = %d, icmp_code = %d\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_type, icmp->icmp_code);
	}
}



/* 显示发送和接收数据报的个数，并计算丢包率 */
void statistics(int signo)
{
    printf("\n----------- %s ping statistics -----------\n", Sock_ntop_host(pr->sarecv, pr->salen));
    int lost = 100*(nsent-nrecv)/nsent;
    printf("%d packets transmitted, %d received, %d packet lost\n", nsent, nrecv, lost);
    close(sockfd);
    exit(1);
}


void
init_v6()
{
#ifdef IPV6
	int on = 1;

	if (verbose == 0) {
		/* install a filter that only passes ICMP6_ECHO_REPLY unless verbose */
		struct icmp6_filter myfilt;
		ICMP6_FILTER_SETBLOCKALL(&myfilt);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &myfilt);
		setsockopt(sockfd, IPPROTO_IPV6, ICMP6_FILTER, &myfilt, sizeof(myfilt));
		/* ignore error return; the filter is an optimization */
	}

	/* ignore error returned below; we just won't receive the hop limit */
#ifdef IPV6_RECVHOPLIMIT
	/* RFC 3542 */
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
#else
	/* RFC 2292 */
	setsockopt(sockfd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
#endif
#endif
}

void
proc_v6(char *ptr, ssize_t len, struct msghdr *msg, struct timeval* tvrecv)
{
#ifdef	IPV6
	double				rtt;
	struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;
	struct cmsghdr		*cmsg;
	int					hlim;

	icmp6 = (struct icmp6_hdr *) ptr;
	if (len < 8)
		return;				/* malformed packet */

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (len < 16)
			return;			/* not enough data to use */

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		hlim = -1;
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				cmsg->cmsg_type == IPV6_HOPLIMIT) {
				hlim = *(u_int32_t *)CMSG_DATA(cmsg);
				break;
			}
		}
		printf("%d bytes from %s: seq=%u, hlim=",
				len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_seq);
		if (hlim == -1)
			printf("???");	/* ancillary data missing */
		else
			printf("%d", hlim);
		printf(", rtt=%.3f ms\n", rtt);
        nrecv++;
	} else if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
	}
#endif	/* IPV6 */
}