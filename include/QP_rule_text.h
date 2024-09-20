#ifndef CLASS_QR_RULE_H
#define CLASS_QR_RULE_H

#define QP_RE_MOD_CASELESS 1
#define QP_RE_MOD_GLOBAL 2

struct _Query_Processor_rule_t;
typedef struct _Query_Processor_rule_t QP_rule_t;

class QP_rule_text_hitsonly {
	public:
	char** pta;
	QP_rule_text_hitsonly(QP_rule_t *QPr);
	~QP_rule_text_hitsonly();
};

class QP_rule_text {
	public:
	char** pta;
	int num_fields;
	QP_rule_text();
	/*virtual*/ ~QP_rule_text();
};

#endif // CLASS_QR_RULE_H
