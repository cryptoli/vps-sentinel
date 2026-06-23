import { CalendarClock, ChevronDown, ChevronLeft, ChevronRight, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Language } from "@/types";

type SelectValue = string | number;

export interface SelectOption<T extends SelectValue> {
  value: T;
  label: string;
}

export function SelectMenu<T extends SelectValue>({
  value,
  options,
  onChange,
  ariaLabel,
  className = "",
}: {
  value: T;
  options: Array<SelectOption<T>>;
  onChange: (value: T) => void;
  ariaLabel: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const selected = useMemo(
    () => options.find((option) => String(option.value) === String(value)) ?? options[0],
    [options, value],
  );

  useEffect(() => {
    if (!open) return undefined;
    function handlePointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div className={`select-menu ${className}`} ref={rootRef}>
      <button
        className="select-trigger"
        type="button"
        aria-label={ariaLabel}
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <span>{selected?.label ?? String(value)}</span>
        <ChevronDown size={15} />
      </button>
      {open && (
        <div className="select-popover" role="listbox" aria-label={ariaLabel}>
          {options.map((option) => (
            <button
              className={String(option.value) === String(value) ? "active" : ""}
              key={String(option.value)}
              type="button"
              role="option"
              aria-selected={String(option.value) === String(value)}
              onClick={() => {
                onChange(option.value);
                setOpen(false);
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function TextField({
  label,
  value,
  placeholder,
  type = "text",
  icon,
  className = "",
  onChange,
}: {
  label?: string;
  value: string;
  placeholder?: string;
  type?: "text" | "password" | "search";
  icon?: React.ReactNode;
  className?: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className={`control-field ${className}`}>
      {label && <span className="control-label">{label}</span>}
      <span className="control-input-wrap">
        {icon && <span className="control-icon">{icon}</span>}
        <input
          className="control-input"
          type={type}
          value={value}
          placeholder={placeholder}
          onChange={(event) => onChange(event.target.value)}
        />
      </span>
    </label>
  );
}

export function DateTimeField({
  label,
  value,
  language,
  onChange,
}: {
  label: string;
  value: string;
  language: Language;
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const pickerValue = normalizeDateTime(value);
  const selectedDate = useMemo(() => parseDateTime(pickerValue), [pickerValue]);
  const [viewDate, setViewDate] = useState<Date>(() => selectedDate ?? new Date());
  const monthLabel = useMemo(() => formatMonth(viewDate, language), [language, viewDate]);
  const days = useMemo(() => calendarDays(viewDate, selectedDate), [selectedDate, viewDate]);
  const time = selectedDate ?? viewDate;

  useEffect(() => {
    if (selectedDate) setViewDate(selectedDate);
  }, [selectedDate?.getFullYear(), selectedDate?.getMonth()]);

  useEffect(() => {
    if (!open) return undefined;
    function handlePointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  function commit(nextDate: Date) {
    onChange(toDateTimeValue(nextDate));
  }

  function selectDay(date: Date) {
    const nextDate = new Date(date);
    nextDate.setHours(time.getHours(), time.getMinutes(), 0, 0);
    commit(nextDate);
  }

  function shiftTime(part: "hour" | "minute", delta: number) {
    const nextDate = selectedDate ? new Date(selectedDate) : new Date(viewDate);
    if (part === "hour") {
      nextDate.setHours((nextDate.getHours() + delta + 24) % 24);
    } else {
      nextDate.setMinutes((nextDate.getMinutes() + delta + 60) % 60);
    }
    commit(nextDate);
  }

  return (
    <div className={`control-field date-field ${open ? "date-field-open" : ""}`} ref={rootRef}>
      <button className="control-label date-label" type="button" onClick={() => setOpen(true)}>
        {label}
      </button>
      <button
        className="control-input-wrap date-trigger"
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <span className="control-icon"><CalendarClock size={15} /></span>
        <span className={`date-display ${pickerValue ? "" : "is-empty"}`}>
          {pickerValue ? displayDateTime(pickerValue) : "yyyy/mm/dd --:--"}
        </span>
        <ChevronDown className="date-chevron" size={15} />
      </button>
      {open && (
        <div className="date-popover" role="dialog" aria-label={label}>
          <div className="date-popover-head">
            <button className="date-nav-button" type="button" aria-label="previous month" onClick={() => setViewDate(addMonths(viewDate, -1))}>
              <ChevronLeft size={16} />
            </button>
            <strong>{monthLabel}</strong>
            <button className="date-nav-button" type="button" aria-label="next month" onClick={() => setViewDate(addMonths(viewDate, 1))}>
              <ChevronRight size={16} />
            </button>
          </div>
          <div className="date-weekdays">
            {weekdayLabels(language).map((day) => <span key={day}>{day}</span>)}
          </div>
          <div className="date-grid">
            {days.map((day) => (
              <button
                className={[
                  day.inMonth ? "" : "is-muted",
                  day.isToday ? "is-today" : "",
                  day.isSelected ? "active" : "",
                ].filter(Boolean).join(" ")}
                key={day.key}
                type="button"
                onClick={() => selectDay(day.date)}
              >
                {day.date.getDate()}
              </button>
            ))}
          </div>
          <div className="date-time-row">
            <span>{language === "zh" ? "时间" : "Time"}</span>
            <div className="time-wheel" aria-label={language === "zh" ? "选择时间" : "Select time"}>
              <button type="button" onClick={() => shiftTime("hour", -1)}><ChevronLeft size={14} /></button>
              <strong>{pad(time.getHours())}</strong>
              <button type="button" onClick={() => shiftTime("hour", 1)}><ChevronRight size={14} /></button>
              <em>:</em>
              <button type="button" onClick={() => shiftTime("minute", -5)}><ChevronLeft size={14} /></button>
              <strong>{pad(time.getMinutes())}</strong>
              <button type="button" onClick={() => shiftTime("minute", 5)}><ChevronRight size={14} /></button>
            </div>
          </div>
          <div className="date-actions">
            <button
              className="ghost-button compact"
              type="button"
              onClick={() => {
                onChange("");
                setOpen(false);
              }}
            >
              {language === "zh" ? "清空" : "Clear"}
            </button>
            <button
              className="ghost-button compact"
              type="button"
              onClick={() => {
                const now = new Date();
                setViewDate(now);
                commit(now);
              }}
            >
              {language === "zh" ? "今天" : "Today"}
            </button>
            <button className="primary-button compact" type="button" onClick={() => setOpen(false)}>
              {language === "zh" ? "完成" : "Done"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function SearchField({
  label,
  value,
  placeholder,
  className = "",
  onChange,
}: {
  label?: string;
  value: string;
  placeholder: string;
  className?: string;
  onChange: (value: string) => void;
}) {
  return (
    <TextField
      label={label}
      type="search"
      value={value}
      placeholder={placeholder}
      icon={<Search size={16} />}
      className={`search-control ${className}`}
      onChange={onChange}
    />
  );
}

export function TextAreaField({
  value,
  placeholder,
  onChange,
}: {
  value: string;
  placeholder: string;
  onChange: (value: string) => void;
}) {
  return (
    <textarea
      className="textarea-control"
      value={value}
      placeholder={placeholder}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

function displayDateTime(value: string): string {
  return value.replace("T", " ").replace(/-/g, "/");
}

function normalizeDateTime(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const normalized = trimmed.replace(/\//g, "-").replace(/\s+/, "T");
  return normalized.slice(0, 16);
}

function parseDateTime(value: string): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function toDateTimeValue(date: Date): string {
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function addMonths(date: Date, delta: number): Date {
  return new Date(date.getFullYear(), date.getMonth() + delta, 1, date.getHours(), date.getMinutes());
}

function calendarDays(viewDate: Date, selectedDate: Date | null) {
  const year = viewDate.getFullYear();
  const month = viewDate.getMonth();
  const first = new Date(year, month, 1);
  const start = new Date(year, month, 1 - first.getDay());
  const today = new Date();
  return Array.from({ length: 42 }, (_, index) => {
    const date = new Date(start.getFullYear(), start.getMonth(), start.getDate() + index);
    return {
      date,
      key: toDateKey(date),
      inMonth: date.getMonth() === month,
      isToday: sameDay(date, today),
      isSelected: Boolean(selectedDate && sameDay(date, selectedDate)),
    };
  });
}

function formatMonth(date: Date, language: Language): string {
  return new Intl.DateTimeFormat(language === "zh" ? "zh-CN" : "en-US", {
    year: "numeric",
    month: "long",
  }).format(date);
}

function weekdayLabels(language: Language): string[] {
  return language === "zh" ? ["日", "一", "二", "三", "四", "五", "六"] : ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
}

function sameDay(left: Date, right: Date): boolean {
  return left.getFullYear() === right.getFullYear()
    && left.getMonth() === right.getMonth()
    && left.getDate() === right.getDate();
}

function toDateKey(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}
