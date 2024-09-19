/*----------------------------------------------------------------------------
 * Name:    Secure_Functions.h
 * Purpose: Function and Typedef Declarations to include into NonSecure Application.
 *----------------------------------------------------------------------------*/

/* Define typedef for NonSecure callback function */ 
typedef int32_t (*NonSecure_funcptr)(uint32_t);

/* Function declarations for Secure functions called from NonSecure application */
extern void    Secure_printf (char*);
extern void    test_llvm_nsc (int count);