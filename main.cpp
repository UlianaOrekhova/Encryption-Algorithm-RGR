#include <iostream>
#include <fstream>
//#include <math>
//
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstdint>
#include <algorithm>
#include <cctype>
//#include <stdexcept>

using namespace std;

vector<uint8_t> rd_f(const string& p)
    { ifstream f(p, ios::binary);
    if(!f) throw runtime_error("err");
    vector<uint8_t> d((istreambuf_iterator<char>(f)), {});
    return d;}

void wr_f(const string& p, const vector<uint8_t>& d)
{
    ofstream f(p, ios::binary);
    if(!f) throw runtime_error("err");
    f.write((const char*)d.data(), d.size());
}

string b2h(const vector<uint8_t>& d)
{
    stringstream ss;
    ss << hex<< uppercase << setfill('0');
    for(uint8_t b :d) ss << setw(2) << (int)b;
    return ss.str();
}

int h2v(char c)
{
if(c >= '0' && c <= '9') return c - '0';
if(c >= 'a' && c <= 'f') return c - 'a' + 10;
if(c >= 'A' && c <= 'F') return c - 'A' + 10;
return -1;
}

vector<uint8_t> h2b(const string& txt)
{
string s = "";
for(char c : txt) if(!isspace((unsigned char)c)) s += c;
if(s.empty() || s.size() % 2 != 0) throw runtime_error("err");
vector<uint8_t> res;
for(size_t i = 0; i < s.size(); i += 2){
    int a1 = h2v(s[i]);
    int a2 = h2v(s[i+1]);
    if(a1 < 0 || a2 < 0) throw runtime_error("err");
    res.push_back((uint8_t)(a1 * 16 + a2));
}
return res;
}

bool is_num(const string& s) 
{
    if(s.empty()) return false;
    for(char c : s) if(!isdigit((unsigned char)c)) return false;
    return true;
}

uint64_t m_pow(uint64_t a, uint64_t e, uint64_t m){
    uint64_t res = 1; // a^e mod m
    a %= m; 
    while(e > 0){
    if(e & 1) res = (res * a) % m;
    a = (a * a) % m;
    e >>= 1;
    }
    return res;
    }

int64_t gcd_f(int64_t a, int64_t b){ 
while(b != 0){
int64_t t = a % b;
a = b;
b = t;
}
return a;
}

int64_t m_inv(int64_t a, int64_t m){
int64_t r0 = a, r1 = m;
int64_t s0 = 1, s1 = 0;
while(r1 != 0){
int64_t q = r0 / r1;
int64_t tmp = r0 - q * r1;
r0 = r1; r1 = tmp;
tmp = s0 - q * s1;
s0 = s1; s1 = tmp;
}
if(r0 != 1) throw runtime_error("err");
s0 %= m;
if(s0 < 0) s0 += m;
return s0;
}

bool is_p(int n)
{
    if(n < 2) return false;
    if(n % 2 == 0) return n == 2;
    for(int d = 3; d * d <= n; d += 2) if(n % d == 0) return false;
    return true;
}

int rnd_i(int l, int r)
{
static random_device rd;
static mt19937 gen(rd());
uniform_int_distribution<int> dist(l, r);
return dist(gen);
}

void save_txt(const string& p, const string& txt)
{
ofstream f(p);
if(!f) throw runtime_error("err");
f << txt;
}

string load_txt(const string& p)
{
ifstream f(p);
if(!f) throw runtime_error("err");
string txt((istreambuf_iterator<char>(f)), {});
return txt;
}

vector<string> split_s(const string& s)
{
stringstream ss(s);
vector<string> res;
string w;
while(ss >> w) res.push_back(w);
return res;
}

void print_txt(const vector<uint8_t>& d)
{
bool ok = true;
for(uint8_t b : d){
if(!(b == '\n' || b == '\r' || b == '\t' || (b >= 32 && b <= 126))){
ok = false;
break;
}
}
if(ok) cout << "Текст: " << string(d.begin(), d.end()) << "\n";
else cout << "Бинарные данные.\n";
}

struct RKey { uint32_t p, q, n, e, d; };

RKey gen_rsa()
{
RKey k;
    do 
    {
    k.p = rnd_i(211, 251);
    if(k.p % 2 == 0) k.p--;
    while(!is_p(k.p)) k.p -= 2;
    k.q = rnd_i(211, 251);
    if(k.q % 2 == 0) k.q--;
    while(!is_p(k.q)) k.q -= 2;
    } while(k.p == k.q);
    k.n = k.p * k.q;
    uint64_t phi = (uint64_t)(k.p - 1) * (k.q - 1);
    k.e = 17;
    if(gcd_f(k.e, phi) != 1){
    k.e = 3;
while(gcd_f(k.e, phi) != 1) k.e += 2;
}
    k.d = (uint32_t)m_inv(k.e, phi);
    return k;
}

string rsa2str(const RKey& k)
{
return to_string(k.p) + " " + to_string(k.q) + " " + to_string(k.n) + " " + to_string(k.e) + " " + to_string(k.d);
}

RKey load_rsa(const string& p)
{
vector<string> v = split_s(load_txt(p));
if(v.size() != 5) throw runtime_error("err");
for(auto& s : v) if(!is_num(s)) throw runtime_error("err");
RKey k;
k.p = stoul(v[0]); k.q = stoul(v[1]); k.n = stoul(v[2]); k.e = stoul(v[3]); k.d = stoul(v[4]);
if(k.n <= 255) throw runtime_error("err");
return k;
}

vector<uint8_t> rsa_enc(const vector<uint8_t>& d, const RKey& k){
if(k.n <= 255 || k.n > 65535) throw runtime_error("err");
vector<uint8_t> res;
res.reserve(d.size() * 2);
for(uint8_t b : d){
uint32_t c = (uint32_t)m_pow(b, k.e, k.n);
res.push_back((c >> 8) & 0xFF);
res.push_back(c & 0xFF);
}
return res;
}

vector<uint8_t> rsa_dec(const vector<uint8_t>& d, const RKey& k){
if(d.size() % 2 != 0) throw runtime_error("err");
vector<uint8_t> res;
res.reserve(d.size() / 2);
for(size_t i = 0; i < d.size(); i += 2){
uint32_t c = ((uint32_t)d[i] << 8) | d[i+1];
uint32_t m = (uint32_t)m_pow(c, k.d, k.n);
if(m > 255) throw runtime_error("err");
res.push_back((uint8_t)m);
}
return res;
}

struct EKey { uint32_t p, g, x, y; };

EKey gen_eg()
{
EKey k;
    k.p = 467;
    k.g = 2;
    k.x = rnd_i(2, k.p - 2);
    k.y = (uint32_t)m_pow(k.g, k.x, k.p);
    return k;
}

string eg2str(const EKey& k)
{
return to_string(k.p) + " " + to_string(k.g) + " " + to_string(k.x) + " " + to_string(k.y);
}

EKey load_eg(const string& p)
{
    vector<string> v = split_s(load_txt(p));
    if(v.size() != 4) throw runtime_error("err");
    for(auto& s : v) if(!is_num(s)) throw runtime_error("err");
    EKey k;
    k.p = stoul(v[0]); k.g = stoul(v[1]); k.x = stoul(v[2]); k.y = stoul(v[3]);
    if(k.p <= 255 || k.x <= 1 || k.x >= k.p - 1) throw runtime_error("err");
    return k;
}

vector<uint8_t> eg_enc(const vector<uint8_t>& d, const EKey& k)
{
vector<uint8_t> res;
res.reserve(d.size() * 4);
for(uint8_t b : d){
    uint32_t r_k = rnd_i(2, k.p - 2);
    uint32_t c1 = (uint32_t)m_pow(k.g, r_k, k.p);
    uint32_t s = (uint32_t)m_pow(k.y, r_k, k.p);
    uint32_t c2 = ((uint32_t)b * s) % k.p;
    res.push_back((c1 >> 8) & 0xFF); res.push_back(c1 & 0xFF);
    res.push_back((c2 >> 8) & 0xFF); res.push_back(c2 & 0xFF);}
return res;
}
vector<uint8_t> eg_dec(const vector<uint8_t>& d, const EKey& k){
if(d.size() % 4 != 0) 
throw runtime_error("err");
vector<uint8_t> res;
res.reserve(d.size() / 4);
for(size_t i = 0; i < d.size(); i += 4)
{
uint32_t c1 = ((uint32_t)d[i] << 8) | d[i+1];
uint32_t c2 = ((uint32_t)d[i+2] << 8) | d[i+3];
uint32_t s = (uint32_t)m_pow(c1, k.x, k.p);
uint32_t inv = (uint32_t)m_inv(s, k.p);
uint32_t m = ((uint64_t)c2 * inv) % k.p;
if(m > 255) throw runtime_error("err");
res.push_back((uint8_t)m);}return res;}

struct WKey 
{ uint32_t k[4]; };

uint32_t b2w(const uint8_t* p)
{return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);}

void w2b(uint32_t x, uint8_t* p)
{
p[0] = x & 0xFF; p[1] = (x >> 8) & 0xFF;
p[2] = (x >> 16) & 0xFF; p[3] = (x >> 24) & 0xFF;
}

string w2hex(const WKey& k)
{
vector<uint8_t> b(16);
for(int i = 0; i < 4; ++i) w2b(k.k[i], b.data() + i * 4);
return b2h(b);
}

WKey gen_wake(){
WKey k;
for(int i = 0; i < 4; i++) k.k[i] = ((uint32_t)rnd_i(0, 0xFFFF) << 16) | (uint32_t)rnd_i(0, 0xFFFF);
return k;
}

WKey load_wake(const string& p)
{
vector<uint8_t> b = h2b(load_txt(p));
if(b.size() != 16) throw runtime_error("err");
WKey k;
for(int i = 0; i < 4; ++i) k.k[i] = b2w(b.data() + i * 4);
return k;}

vector<uint32_t> wake_tbl(const WKey& k)
{
static const uint32_t TT[8] = { 0x726a8f3bU, 0xe69a3b5cU, 0xd3c71fe5U, 0xab3c73d2U, 0x4d3a8eb3U, 0x0396d6e8U, 0x3d4c2f7aU, 0x9ee27cf3U };
vector<uint32_t> t(257);
for(int i = 0; i < 4; ++i) t[i] = k.k[i];
for(int p = 4; p < 256; ++p){
uint32_t x = t[p - 4] + t[p - 1];
t[p] = (x >> 3) ^ TT[x & 7];
}
for(int p = 0; p < 23; ++p) t[p] += t[p + 89];
uint32_t x = t[33];
uint32_t z = (t[59] | 0x01000001U) & 0xff7fffffU;
for(int p = 0; p < 256; ++p){
x = (x & 0xff7fffffU) + z;
t[p] = (t[p] & 0x00ffffffU) ^ x;
}
t[256] = t[0];
x &= 0xffU;
for(int p = 0; p < 256; ++p){
x = (t[p ^ x] ^ x) & 0xffU;
t[p] = t[x];
t[x] = t[p + 1];
}
return t;
}

uint32_t wake_mix(uint32_t x, uint32_t y, const vector<uint32_t>& t){
uint32_t s = x + y;
return ((s >> 8) & 0x00ffffffU) ^ t[s & 0xffU];
}

vector<uint32_t> wake_proc(const vector<uint32_t>& in, const WKey& k, bool dec){
vector<uint32_t> t = wake_tbl(k);
vector<uint32_t> out = in;
uint32_t r3 = k.k[0], r4 = k.k[1], r5 = k.k[2], r6 = k.k[3];
for(size_t i = 0; i < out.size(); ++i){
uint32_t r1 = out[i];
uint32_t r2 = r1 ^ r6;
out[i] = r2;
if(!dec) r3 = wake_mix(r3, r2, t);
else r3 = wake_mix(r3, r1, t);
r4 = wake_mix(r4, r3, t);
r5 = wake_mix(r5, r4, t);
r6 = wake_mix(r6, r5, t);
}
return out;
}

vector<uint8_t> wake_enc(const vector<uint8_t>& d, const WKey& k)
{
vector<uint8_t> prep(4 + d.size());
uint32_t len = (uint32_t)d.size();
w2b(len, prep.data());
copy(d.begin(), d.end(), prep.begin() + 4);
while(prep.size() % 4 != 0) prep.push_back(0);
vector<uint32_t> w(prep.size() / 4);
for(size_t i = 0; i < w.size(); ++i) w[i] = b2w(prep.data() + i * 4);
w = wake_proc(w, k, false);

vector<uint8_t> res(w.size() * 4);
for(size_t i = 0; i < w.size(); ++i) w2b(w[i], res.data() + i * 4);

return res;
}

vector<uint8_t> wake_dec(const vector<uint8_t>& d, const WKey& k){
if(d.size() % 4 != 0 || d.size() < 4) throw runtime_error("err");
vector<uint32_t> w(d.size() / 4);
for(size_t i = 0; i < w.size(); ++i) w[i] = b2w(d.data() + i * 4);
w = wake_proc(w, k, true);
vector<uint8_t> prep(w.size() * 4);
for(size_t i = 0; i < w.size(); ++i) w2b(w[i], prep.data() + i * 4);
uint32_t len = b2w(prep.data());
if(len > prep.size() - 4) throw runtime_error("err");
return vector<uint8_t>(prep.begin() + 4, prep.begin() + 4 + len);
}

int alg_type = 0;

vector<uint8_t> do_enc(int alg, const vector<uint8_t>& d, const string& kp){
if(alg == 1) return rsa_enc(d, load_rsa(kp));
if(alg == 2) return eg_enc(d, load_eg(kp));
return wake_enc(d, load_wake(kp));
}

vector<uint8_t> do_dec(int alg, const vector<uint8_t>& d, const string& kp){
if(alg == 1) return rsa_dec(d, load_rsa(kp));
if(alg == 2) return eg_dec(d, load_eg(kp));
return wake_dec(d, load_wake(kp));
}

void gen_k(int alg)
{
string kp;
cout << "файл ключа: ";
getline(cin, kp);
if(kp.empty()) throw runtime_error("err");
if(alg == 1){
RKey k = gen_rsa();
save_txt(kp, rsa2str(k));
} else if(alg == 2){

EKey k = gen_eg();
save_txt(kp, eg2str(k));
} else {
WKey k = gen_wake();
save_txt(kp, w2hex(k));
}
cout << "готов\n";
}

void enc_t(int alg){
string kp, str;
cout << "ключ: "; 
getline(cin, kp);
cout << "текст: "; 
getline(cin, str);
if(str.empty()) throw runtime_error("err");
vector<uint8_t> in(str.begin(), str.end());

vector<uint8_t> res = do_enc(alg, in, kp);

cout << "hex: " << b2h(res) << "\n";
}

void dec_t(int alg){
string kp, hstr;
cout << "ключ: ";
 getline(cin, kp);
cout << "hex: "; getline(cin, hstr);
vector<uint8_t> in = h2b(hstr);
vector<uint8_t> res = do_dec(alg, in, kp);
print_txt(res);}
void enc_f(int alg){
string kp, inf, outf;
cout << "ключ: "; getline(cin, kp);
cout << "входной файл: "; getline(cin, inf);
cout << "выходной файл: "; getline(cin, outf);
vector<uint8_t> in = rd_f(inf);
vector<uint8_t> res = do_enc(alg, in, kp);
string hex_out = b2h(res);
wr_f(outf, vector<uint8_t>(hex_out.begin(), hex_out.end()));
cout << "готово\n";}

void dec_f(int alg)
{
    string kp, inf, outf;
    cout << "ключ: "; getline(cin, kp);
    cout << "входной файл: "; getline(cin, inf);
    cout << "выходной файл: "; getline(cin, outf);
    vector<uint8_t> fd = rd_f(inf);
    string hex_str(fd.begin(), fd.end());
    vector<uint8_t> encrypted = h2b(hex_str);
    vector<uint8_t> res = do_dec(alg, encrypted, kp);
    wr_f(outf, res);
cout << "готово\n";
}

void menu_alg(int alg){
    while(true)
    {
    try 
        {
        cout << "\n1. ключ\n2. зашифровать текст\n3. расшифровать текст\n4. зашифровать файл\n5. расшифровать файл\n0. назад\n> ";
        string c;
        getline(cin, c);
        if(c == "0") return;
        if(c == "1") gen_k(alg);
        else if(c == "2") enc_t(alg);
        else if(c == "3") dec_t(alg);
        else if(c == "4") enc_f(alg);
        else if(c == "5") dec_f(alg);
        } 
    catch(const exception& e){
    cout << "ошибка\n";}}}

int main()
{
while(true)
    {
    try 
    {
        cout << "\n1. RSA\n2. ElGamal\n3. WAKE\n0. Exit\n> ";
        string c;
        getline(cin, c);
        if(c == "0") break;
        if(c == "1") menu_alg(1);
        else if(c == "2") menu_alg(2);
        else if(c == "3") menu_alg(3);
    } 
    catch(...)
    {
    cout << "ошибка\n";
    }
    }
return 0;
}