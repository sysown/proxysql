#ifndef CLASS_WEB_INTERFACE
#define CLASS_WEB_INTERFACE

class Web_Interface {
    public:
    Web_Interface() {};
    virtual ~Web_Interface() {};
    virtual void print_version() {};
};

typedef Web_Interface * create_Web_Interface_t();

#endif /* CLASS_WEB_INTERFACE */
