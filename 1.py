def Xor(a,b):#异或
    c=''
    for i in range(len(a)):
        if a[i]==b[i]:
            c+='0'
        else:
            c+='1'
    return c

def add(y1,y2,dlt):#模256加法
    y11=y1[::-1]
    y22=y2[::-1]
    sumofy11 = 0
    sumofy22 = 0
    for i in range(len(y11)):
        b=int(y11[i])*pow(2,i)
        sumofy11+=b
    for i in range(len(y22)):
        b=int(y22[i])*pow(2,i)
        sumofy22+=b
    sum=sumofy11+sumofy22+dlt
    sum=sum%256
    r=bin(sum)
    r=str(r)
    ret=r.replace("0b","")
    ret=ret.zfill(8)
    return ret

def R(s):#八位二进制数循环左移2位（这里应该有更好的方法)
    ret=''
    ret += s[2]
    ret += s[3]
    ret += s[4]
    ret += s[5]
    ret += s[6]
    ret += s[7]
    ret += s[0]
    ret += s[1]
    return ret

def S(x1,x2,delta):#移位函数
    W=add(x1,x2,delta)
    ret=R(W)
    return ret

def fk(alpha,beta):#子密钥产生函数
    a0=alpha[:8]
    a1=alpha[8:16]
    a2=alpha[16:24]
    a3=alpha[24:32]
    b0 = beta[:8]
    b1 = beta[8:16]
    b2 = beta[16:24]
    b3 = beta[24:32]
    h1=Xor(a0,a1)
    h2=Xor(a2,a3)
    fk1 = S(h1, Xor(h2, b0), 1)
    fk2 = S(h2, Xor(fk1, b1), 0)
    fk0 = S(a0, Xor(fk1, b2), 0)
    fk3 = S(a3, Xor(fk2, b3), 1)
    ck=fk0+fk1+fk2+fk3
    return ck

def f(alpha,beta):#加密函数
    a0 = alpha[:8]
    a1 = alpha[8:16]
    a2 = alpha[16:24]
    a3 = alpha[24:32]
    b0 = beta[:8]
    b1 = beta[8:16]
    g1=Xor(Xor(a1,b0),a0)
    g2=Xor(Xor(a2,b1),a3)
    f1=S(g1,g2,1)
    f2=S(g2,f1,0)
    f3=S(a3,f1,1)
    f0=S(a0,f1,0)
    ret=f0+f1+f2+f3
    return ret

key=[]#保存了所有子密钥，共12个
def chikey(a,b,d):#子密钥生成（主体）
    if len(key) > 11:
        return key
    Di=a
    Ai=b
    Bi=fk(a,Xor(b,d))
    key.append(Bi[:16])
    key.append(Bi[-16:])
    chikey(Ai,Bi,Di)

def childkey(k):#子密钥生成（初始化部分）
    A0 = k[:32]
    B0 = k[-32:]
    D0 = '0000000000000000000000000000000000000000000000000000000000000000'
    chikey(A0, B0, D0)

def initofencode(l011,r011):#加密算法的初始运算部分
    key45=key[4]+key[5]
    l01=Xor(l011,key45)
    key67=key[6]+key[7]
    r01=Xor(r011,key67)
    l0=l01
    r0=Xor(r01,l01)
    return l0,r0

fourinterationofencode=[]#保存了所有加密运算四次迭代的运算结果
def fourencode(L,R):#加密运算的四次迭代
    Li=R
    Ri=Xor(L,f(R,key[len(fourinterationofencode)]))
    fourinterationofencode.append([Li,Ri])
    if len(fourinterationofencode) > 3:
        return fourinterationofencode
    fourencode(Li,Ri)

def endofencode():#加密运算的末尾运算
    l4=fourinterationofencode[3][0]
    r4=fourinterationofencode[3][1]
    r41=r4
    l41=Xor(l4,r4)
    key89=key[8]+key[9]
    key1011=key[10]+key[11]
    r411=Xor(r41,key89)
    l411=Xor(l41,key1011)
    ret=l411+r411
    return ret

def encode(m):#加密运算过程
    L011=m[:32]
    R011=m[-32:]
    l,r=initofencode(L011,R011)
    fourencode(l,r)
    c=endofencode()
    return c

def initofdecode(l411,r411):#解密算法的初始运算部分
    key89 = key[8] + key[9]
    key1011 = key[10] + key[11]
    r41 = Xor(r411, key89)
    l41 = Xor(l411, key1011)
    r4=r41
    l4 = Xor(l41, r41)
    return l4,r4

fourinterationofdecode=[]#保存了所有解密运算四次迭代的运算结果
def fourdecode(L,R):#解密运算的四次迭代
    Ri=L
    Li=Xor(R,f(L,key[3-len(fourinterationofdecode)]))
    fourinterationofdecode.append([Li,Ri])
    if len(fourinterationofdecode) > 3:
        return fourinterationofdecode
    fourdecode(Li,Ri)

def endofdecode():#解密运算的末尾运算
    l0 = fourinterationofdecode[3][0]
    r0 = fourinterationofdecode[3][1]
    l01=l0
    r01=Xor(l0,r0)
    key67 = key[6] + key[7]
    key45 = key[4] + key[5]
    r011=Xor(r01,key67)
    l011=Xor(l01,key45)
    m=l011+r011
    return m

def decode(c):#解密运算过程
    l411 = c[:32]
    r411 = c[-32:]
    l, r = initofdecode(l411, r411)
    fourdecode(l, r)
    m = endofdecode()
    return m

def main():
    m = '0011101011010111001010101100001011010111101110000101110101001000'#明文
    k = '1001001010010010111110000110000111010101001110000100100011011110'#密钥
    print(m)
    childkey(k)#生成子密钥
    c = encode(m)#加密
    print(c)
    mes = decode(c)#解密
    print(mes)
    if mes==m:
        print("解密成功！")
    else:
        print("解密失败")

if __name__ == '__main__':
  main()
