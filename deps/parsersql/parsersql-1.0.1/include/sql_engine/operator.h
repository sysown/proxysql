#ifndef SQL_ENGINE_OPERATOR_H
#define SQL_ENGINE_OPERATOR_H

#include "sql_engine/row.h"

namespace sql_engine {

class Operator {
public:
    virtual ~Operator() = default;
    virtual void open() = 0;
    virtual bool next(Row& out) = 0;
    virtual void close() = 0;
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATOR_H
