/*
 * LCD Display API
 */

#ifndef LIQUID_CRYSTAL_H
#define LIQUID_CRYSTAL_H

typedef struct LiquidCrystalStruct{
	unsigned int id;
} LiquidCrystal;

void lcd_begin(LiquidCrystal* lcd, unsigned int cols, unsigned int rows)
{

}
void lcd_clear(LiquidCrystal* lcd)
{

}
void lcd_print(LiquidCrystal* lcd, char* output, int len)
{

}
void lcd_setCursor(LiquidCrystal* lcd, int x, int y)
{
    
}

#endif /* LIQUID_CRYSTAL_H */