import { DEFAULT_LIMIT, TIME_PRESETS } from "@/lib/datasets";
import { rangePreset } from "@/lib/api";
import { translate } from "@/lib/i18n";
import type { DatasetState, Language } from "@/types";
import { DateTimeField, SearchField, SelectMenu } from "@/components/Controls";

export function Filters({
  state,
  language,
  onChange,
}: {
  state: DatasetState;
  language: Language;
  onChange: (patch: Partial<DatasetState>) => void;
}) {
  return (
    <section className="filter-card">
      <div className="quick-ranges">
        {TIME_PRESETS.map((preset) => (
          <button
            className={`chip ${state.preset === preset ? "active" : ""}`}
            key={preset}
            type="button"
            onClick={() => onChange({ ...rangePreset(preset), preset, offset: 0 })}
          >
            {translate(language, `range_${preset}`)}
          </button>
        ))}
      </div>
      <div className="filter-fields">
        <DateTimeField label={translate(language, "from")} value={state.from} language={language} onChange={(from) => onChange({ from, preset: "", offset: 0 })} />
        <DateTimeField label={translate(language, "to")} value={state.to} language={language} onChange={(to) => onChange({ to, preset: "", offset: 0 })} />
        <div className="control-field page-size-field">
          <span className="control-label">{translate(language, "pageSize")}</span>
          <SelectMenu
            value={state.limit}
            ariaLabel={translate(language, "pageSize")}
            options={[10, 25, 50, 100, 200].map((size) => ({ value: size, label: String(size) }))}
            onChange={(limit) => onChange({ limit, offset: 0 })}
          />
        </div>
        <SearchField
          className="search-field"
          label={translate(language, "search")}
          value={state.query}
          placeholder={translate(language, "searchPlaceholder")}
          onChange={(query) => onChange({ query, offset: 0 })}
        />
        <button className="ghost-button" type="button" onClick={() => onChange({ from: "", to: "", preset: "", offset: 0, limit: DEFAULT_LIMIT, query: "" })}>
          {translate(language, "reset")}
        </button>
      </div>
    </section>
  );
}
