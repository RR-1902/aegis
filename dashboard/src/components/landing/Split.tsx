import { Fragment, type ElementType } from 'react';

type SplitProps = {
  as?: ElementType;
  text: string;
  className?: string;
  id?: string;
};

/** A heading split into words that rise into place as it scrolls into view. */
export default function Split({ as: Tag = 'h2', text, className, id }: SplitProps) {
  const words = text.split(' ');
  return (
    <Tag className={className} id={id} data-split="">
      {words.map((word, index) => (
        <Fragment key={`${word}-${index}`}>
          <span className="word">
            <span className="word__inner">{word}</span>
          </span>
          {index < words.length - 1 ? ' ' : null}
        </Fragment>
      ))}
    </Tag>
  );
}
