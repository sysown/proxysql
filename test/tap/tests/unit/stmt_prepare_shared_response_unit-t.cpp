#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "MySQL_Protocol.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Session.h"
#include "mysql_connection.h"
#include <cstring>

static uint16_t u16(const unsigned char* p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint32_t u32(const unsigned char* p) { uint32_t v; memcpy(&v,p,4); return v; }
static void clear(MySQL_Data_Stream& s) {
    for (unsigned i=0;i<s.PSarrayOUT->len;i++) { auto p=s.PSarrayOUT->pdata[i]; l_free(p.size,p.ptr); }
    s.PSarrayOUT->len=0;
}
int main() {
    plan(NO_PLAN);
    test_init_minimal();
    {
        MySQL_Session session; session.connections_handler=true;
        MySQL_Data_Stream stream; stream.sess=&session; stream.PSarrayOUT=new PtrSizeArray();
        MySQL_Data_Stream* ds=&stream; MySQL_Protocol protocol; protocol.init(&ds,nullptr,&session);
        MySQL_Connection conn; stream.myconn=&conn;
        char empty[]="", col[]="column_x"; MYSQL_FIELD f{};
        f.db=empty; f.table=empty; f.org_table=empty; f.name=col; f.org_name=empty;
        f.charsetnr=63; f.length=32; f.type=MYSQL_TYPE_VAR_STRING; MYSQL_FIELD* fields[]={&f};
        ok(protocol.generate_STMT_PREPARE_RESPONSE(1, 42, 1, 1, fields, 7, SERVER_STATUS_AUTOCOMMIT), "explicit metadata generates response");
        ok(stream.PSarrayOUT->len==5, "header, parameter, EOF, column, EOF emitted");
        if (stream.PSarrayOUT->len==5) {
            auto h=static_cast<unsigned char*>(stream.PSarrayOUT->pdata[0].ptr);
            ok(h[3]==1 && h[4]==0 && u32(h+5)==42 && u16(h+9)==1 && u16(h+11)==1 && u16(h+14)==7, "prepare header contains ID, counts and warnings");
            auto param=static_cast<unsigned char*>(stream.PSarrayOUT->pdata[1].ptr);
            auto eof1=static_cast<unsigned char*>(stream.PSarrayOUT->pdata[2].ptr);
            auto column=static_cast<unsigned char*>(stream.PSarrayOUT->pdata[3].ptr);
            auto eof2=static_cast<unsigned char*>(stream.PSarrayOUT->pdata[4].ptr);
            ok(param[3]==2 && eof1[3]==3 && eof1[4]==0xfe && column[3]==4 && eof2[3]==5 && eof2[4]==0xfe, "metadata packets appear in protocol order");
            ok(column[11] == 8 && memcmp(column+12, "column_x", 8) == 0, "column metadata preserves the supplied name");
            ok(u16(eof1+7)==SERVER_STATUS_AUTOCOMMIT && u16(eof2+7)==SERVER_STATUS_AUTOCOMMIT, "EOF uses supplied autocommit status");
        }
        clear(stream);
        ok(protocol.generate_STMT_PREPARE_RESPONSE(3, 1, 1, 0, nullptr, 0, SERVER_STATUS_IN_TRANS), "parameter-only response succeeds");
        if (stream.PSarrayOUT->len==3) ok(u16(static_cast<unsigned char*>(stream.PSarrayOUT->pdata[2].ptr)+7)==SERVER_STATUS_IN_TRANS, "EOF uses supplied transaction status");
        else ok(false,"parameter-only response contains EOF");
        clear(stream);
        conn.options.client_flag |= CLIENT_DEPRECATE_EOF;
        ok(protocol.generate_STMT_PREPARE_RESPONSE(1, 2, 1, 1, fields, 0, 0) && stream.PSarrayOUT->len==3, "deprecate EOF omits both EOF packets");
        clear(stream);
        ok(protocol.generate_STMT_PREPARE_RESPONSE(1, 3, 0, 0, nullptr, 0, 0) && stream.PSarrayOUT->len==1, "empty metadata emits only header");
        clear(stream);
        ok(!protocol.generate_STMT_PREPARE_RESPONSE(1, 3, 0, 1, nullptr, 0, 0) && !stream.PSarrayOUT->len, "null field array refused before output");
        MYSQL_FIELD* bad[]={nullptr};
        ok(!protocol.generate_STMT_PREPARE_RESPONSE(1, 3, 0, 1, bad, 0, 0) && !stream.PSarrayOUT->len, "null field element refused before output");
        MYSQL_FIELD zero{};
        MYSQL_FIELD* zero_fields[] = {&zero};
        ok(!protocol.generate_STMT_PREPARE_RESPONSE(1, 3, 0, 1, zero_fields, 0, 0) &&
           !stream.PSarrayOUT->len, "zero-initialized field refused before output");
        char** members[] = {&f.db, &f.table, &f.org_table, &f.name, &f.org_name};
        const char* names[] = {"db", "table", "org_table", "name", "org_name"};
        for (unsigned i = 0; i < 5; ++i) {
            char* saved = *members[i];
            *members[i] = nullptr;
            ok(!protocol.generate_STMT_PREPARE_RESPONSE(1, 3, 0, 1, fields, 0, 0) &&
               !stream.PSarrayOUT->len, "null %s refused before output", names[i]);
            *members[i] = saved;
        }
        stream.myconn = nullptr;
    }
    test_cleanup_minimal();
    return exit_status();
}
