use payment_mandate::types::common::Date;
use core::array::ArrayTrait;

const SECONDS_PER_DAY: u64 = 86400;
const DAYS_PER_YEAR: u64 = 365;
const DAYS_PER_4_YEARS: u64 = consteval_int!(365 * 4 + 1);

pub fn get_date(timestamp: u64) ->  Date {

    let days_since_epoch = timestamp / SECONDS_PER_DAY;
    
    let mut year = 1970; // start of unix timestamp
    let mut remaining_days = days_since_epoch;
    
    // Calculate year number
    year = year + 4*(remaining_days / DAYS_PER_4_YEARS) ;
    remaining_days = remaining_days % DAYS_PER_4_YEARS;

    while remaining_days >= DAYS_PER_YEAR {
        if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            if remaining_days >= 366 {
                year += 1;
                remaining_days -= 366;
            } else {
                break;
            }
        } else {
            year += 1;
            remaining_days -= 365;
        }
    };
    
    // Calculate month number
    let is_leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut month_days = array![0_u64];
    if is_leap_year {
        month_days = array![31, 29 , 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,];
    }
    else {
        month_days = array![31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,];
    }
    
    let mut month = 1;
    
    let mut index = 0;

    while index < month_days.len() {

        if remaining_days < *month_days.at(index) {
            break;
        }

        remaining_days = remaining_days - *month_days.at(index);
        month = month + 1;
        index = index + 1;
    };
    
    // Handle days
    let day = remaining_days + 1;
    
    return Date {
        year: year,
        month: month,
        day: day,
    };

}