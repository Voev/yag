#pragma once
#include <cctype>
#include <string>

inline void NameGeneratorFiltering( std::string& name )
{
    for( auto& i : name ) 
    {
        if( !isalpha( i ) && !isdigit( i ) && i != '_' )
        {
            i = '_';
        }
    }
}