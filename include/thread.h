/*
   thread.h

   Header for a Java style thread class in C++.

   ------------------------------------------

   Copyright © 2013 [Vic Hargrave - http://vichargrave.com]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef __thread_h__
#define __thread_h__

#include <pthread.h>

class Thread
{
  public:
    Thread();
    virtual ~Thread();

    int start();
    int join();
    int detach();
    pthread_t self();
    
    virtual void* run() = 0;
    
  private:
    pthread_t  m_tid;
    int        m_running;
    int        m_detached;
};

#endif
