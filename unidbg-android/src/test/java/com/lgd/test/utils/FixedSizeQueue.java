package com.lgd.test.utils;

import java.util.ArrayDeque;
import java.util.Deque;

public class FixedSizeQueue<T> {
    private final int maxSize;
    private final Deque<T> deque;

    public FixedSizeQueue(int maxSize) {
        this.maxSize = maxSize;
        this.deque = new ArrayDeque<>(maxSize);
    }

    public void add(T element) {
        if (deque.size() == maxSize) {
            deque.pollFirst(); // 删除最先添加的元素
        }
        deque.offerLast(element);
    }

    public T peek() {
        return deque.peek();
    }

    public T get(int i) {
        if (i < 0 || i >= deque.size()) {
            return null;
        }
        int currentIndex = 0;
        for (T element : deque) {
            if (currentIndex == i) {
                return element;
            }
            currentIndex++;
        }
        return null;
    }

    public int size() {
        return deque.size();
    }

    public boolean isEmpty() {
        return deque.isEmpty();
    }

    @Override
    public String toString() {
        return deque.toString();
    }
}
