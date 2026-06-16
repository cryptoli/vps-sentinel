use std::str::FromStr;

/// A half-open local-time minute window such as `22:00-07:00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinuteWindow {
    start_minute: u16,
    end_minute: u16,
}

impl MinuteWindow {
    pub fn contains(self, minute_of_day: u16) -> bool {
        if self.start_minute < self.end_minute {
            minute_of_day >= self.start_minute && minute_of_day < self.end_minute
        } else {
            minute_of_day >= self.start_minute || minute_of_day < self.end_minute
        }
    }
}

impl FromStr for MinuteWindow {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (start, end) = value
            .split_once('-')
            .ok_or_else(|| "expected HH:MM-HH:MM".to_string())?;
        let start_minute = parse_minute(start)?;
        let end_minute = parse_minute(end)?;
        if start_minute == end_minute {
            return Err("start and end must be different".to_string());
        }
        Ok(Self {
            start_minute,
            end_minute,
        })
    }
}

pub fn minute_of_day(hour: u32, minute: u32) -> Option<u16> {
    if hour < 24 && minute < 60 {
        Some((hour * 60 + minute) as u16)
    } else {
        None
    }
}

fn parse_minute(value: &str) -> Result<u16, String> {
    let (hour, minute) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("invalid time '{value}', expected HH:MM"))?;
    let hour = hour
        .parse::<u32>()
        .map_err(|_| format!("invalid hour '{hour}'"))?;
    let minute = minute
        .parse::<u32>()
        .map_err(|_| format!("invalid minute '{minute}'"))?;
    minute_of_day(hour, minute).ok_or_else(|| format!("time '{value}' is out of range"))
}

#[cfg(test)]
mod tests {
    use super::{minute_of_day, MinuteWindow};

    #[test]
    fn parses_wrapping_window() -> Result<(), Box<dyn std::error::Error>> {
        let window: MinuteWindow = "22:00-07:00".parse()?;
        assert!(window.contains(minute_of_day(23, 30).ok_or("minute")?));
        assert!(window.contains(minute_of_day(6, 59).ok_or("minute")?));
        assert!(!window.contains(minute_of_day(12, 0).ok_or("minute")?));
        Ok(())
    }

    #[test]
    fn parses_daytime_window() -> Result<(), Box<dyn std::error::Error>> {
        let window: MinuteWindow = "09:00-17:30".parse()?;
        assert!(window.contains(minute_of_day(9, 0).ok_or("minute")?));
        assert!(window.contains(minute_of_day(17, 29).ok_or("minute")?));
        assert!(!window.contains(minute_of_day(17, 30).ok_or("minute")?));
        Ok(())
    }

    #[test]
    fn rejects_invalid_window() {
        assert!("25:00-07:00".parse::<MinuteWindow>().is_err());
        assert!("09:00-09:00".parse::<MinuteWindow>().is_err());
    }
}
