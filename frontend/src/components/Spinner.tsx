export default function Spinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sizeClasses = {
    sm: 'h-5 w-5 border-2',
    md: 'h-8 w-8 border-3',
    lg: 'h-12 w-12 border-4',
  };
  return (
    <div className="flex justify-center items-center py-8">
      <div
        className={`animate-spin rounded-full border-gray-300 border-t-blue-600 ${sizeClasses[size]}`}
      />
    </div>
  );
}
