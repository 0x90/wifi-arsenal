int rand_r( unsigned int *seed )
{
    unsigned int s=*seed;
    unsigned int uret;

    s = (s * 1103515245) + 12345; // permutate seed
    uret = s & 0xffe00000;  // Only use top 11 bits
   
    s = (s * 1103515245) + 12345; // permutate seed
    uret += (s & 0xfffc0000) >> 11;     // Only use top 14 bits
   
    s = (s * 1103515245) + 12345; // permutate seed
    uret += (s & 0xfe000000) >> (11+14);// Only use top 7 bits
   
    retval = (int)(uret & RAND_MAX);
    *seed = s;

    return retval;
   
} 