type StepState = 'idle' | 'active' | 'done';

interface Step {
  label: string;
  state: StepState;
}

interface StepperProps {
  steps: Step[];
}

function StepMarker({ state, index }: { state: StepState; index: number }) {
  if (state === 'done') {
    return (
      <span className="stepper-marker" aria-hidden="true">
        ✓
      </span>
    );
  }
  return (
    <span className="stepper-marker" aria-hidden="true">
      {index + 1}
    </span>
  );
}

export function Stepper({ steps }: StepperProps) {
  return (
    <div className="stepper" role="list">
      {steps.map((step, index) => {
        const isLast = index === steps.length - 1;
        const nextStepDone = !isLast && steps[index].state === 'done';
        return (
          <div key={step.label} className="contents">
            <div className="stepper-step" role="listitem" data-state={step.state}>
              <StepMarker state={step.state} index={index} />
              <span className="stepper-label">{step.label}</span>
            </div>
            {!isLast ? <div className="stepper-bar" data-done={nextStepDone ? 'true' : 'false'} /> : null}
          </div>
        );
      })}
    </div>
  );
}
