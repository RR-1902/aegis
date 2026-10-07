import { useId } from 'react';

type Option = { value: string; label: string; count?: number };

type FilterGroupProps = {
  legend: string;
  name: string;
  value: string;
  options: Option[];
  onChange: (value: string) => void;
};

/** A row of radio buttons drawn as a segmented control. */
export default function FilterGroup({ legend, name, value, options, onChange }: FilterGroupProps) {
  const id = useId();
  return (
    <fieldset className="segmented">
      <legend className="segmented__legend">{legend}</legend>
      <div className="segmented__options">
        {options.map((option) => {
          const optionId = `${id}-${option.value || 'all'}`;
          return (
            <span className="segmented__option" key={option.value || 'all'}>
              <input
                type="radio"
                id={optionId}
                name={name}
                value={option.value}
                checked={value === option.value}
                onChange={() => onChange(option.value)}
              />
              <label htmlFor={optionId}>
                {option.label}
                {option.count !== undefined && <span className="segmented__count">{option.count}</span>}
              </label>
            </span>
          );
        })}
      </div>
    </fieldset>
  );
}
