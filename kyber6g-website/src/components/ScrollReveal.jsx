import { useRef, useEffect, useState } from 'react'

export default function ScrollReveal({ children, className = '', delay = 0, style = {} }) {
    const ref = useRef(null)
    const [isVisible, setIsVisible] = useState(false)

    useEffect(() => {
        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    setIsVisible(true)
                    observer.unobserve(entry.target)
                }
            },
            {
                rootMargin: '0px 0px -50px 0px',
                threshold: 0.1
            }
        )

        if (ref.current) {
            observer.observe(ref.current)
        }

        return () => {
            if (ref.current) observer.unobserve(ref.current)
        }
    }, [])

    const delayClass = delay > 0 ? `reveal-delay-${delay}` : ''

    return (
        <div
            ref={ref}
            className={`reveal ${isVisible ? 'visible' : ''} ${delayClass} ${className}`}
            style={style}
        >
            {children}
        </div>
    )
}
