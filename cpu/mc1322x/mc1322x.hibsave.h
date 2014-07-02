#ifdef LINKERSCRIPT
		
#elseif
#define CONST(type,name,value) \
        const type    __const__ name = value; \
		static const uint32_t	name##_ptr  = 0; \
		static const uint32_t	name##_size = sizeof(value); 	
		
#define CONST_S(type,name,value) \
        const type    __const__ name [] = value; \
		static const uint32_t	name##_ptr  = 0; \
		static const uint32_t	name##_size = sizeof(value); 

#endif